// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestResolveDaemonIPCPathForLifecycleSkipsAttachOnlyValidation(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, ".prod"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	inStorePath := filepath.Join(dataDir, "run", "aplane.sock")

	got, err := resolveDaemonIPCPathForLifecycle(dataDir, inStorePath, false)
	if err != nil {
		t.Fatalf("attach-only resolution error = %v, want nil", err)
	}
	if got != "" {
		t.Fatalf("attach-only daemon path = %q, want empty", got)
	}

	if _, err := resolveDaemonIPCPathForLifecycle(dataDir, inStorePath, true); err == nil ||
		!strings.Contains(err.Error(), "must be outside signer data directory") {
		t.Fatalf("managed-start resolution error = %v, want in-store rejection", err)
	}
}

func TestPrepareDaemonProcessDisabled(t *testing.T) {
	proc, info := prepareDaemonProcessWithDeps("/signer", "/tmp/override.sock", "/tmp/configured.sock", false, daemonTestDeps())
	if proc != nil {
		t.Fatal("process != nil, want nil")
	}
	if info.Status != daemonStatusDisabled {
		t.Fatalf("status = %s, want %s", info.Status, daemonStatusDisabled)
	}
	if info.Owned {
		t.Fatal("Owned = true, want false")
	}
}

func TestPrepareDaemonProcessRefusesMismatchedClientAndDaemonPaths(t *testing.T) {
	deps := daemonTestDeps()
	deps.dial = func(string) (io.Closer, error) {
		t.Fatal("mismatched path was dialed for attachment")
		return nil, nil
	}
	deps.start = func(string, string) (*daemonProcess, error) {
		t.Fatal("daemon started with a mismatched readiness path")
		return nil, nil
	}

	proc, info := prepareDaemonProcessWithDeps("/signer", "/tmp/override.sock", "/tmp/configured.sock", true, deps)
	if proc != nil {
		t.Fatal("process != nil, want refusal")
	}
	if info.Status != daemonStatusFailed {
		t.Fatalf("status = %s, want %s", info.Status, daemonStatusFailed)
	}
	if !strings.Contains(info.Detail, "--no-start-daemon") {
		t.Fatalf("detail = %q, want attach-only remediation", info.Detail)
	}
}

func TestPrepareDaemonProcessAttachesExistingIPC(t *testing.T) {
	deps := daemonTestDeps()
	deps.dial = func(path string) (io.Closer, error) {
		if path != "/tmp/apsigner.sock" {
			t.Fatalf("dial path = %q", path)
		}
		return fakeCloser{}, nil
	}

	proc, info := prepareDaemonProcessWithDeps("/signer", "/tmp/apsigner.sock", "/tmp/apsigner.sock", true, deps)
	if proc != nil {
		t.Fatal("process != nil, want nil")
	}
	if info.Status != daemonStatusAttached {
		t.Fatalf("status = %s, want %s", info.Status, daemonStatusAttached)
	}
	if info.IPCPath != "/tmp/apsigner.sock" {
		t.Fatalf("IPCPath = %q", info.IPCPath)
	}
	if info.Owned {
		t.Fatal("Owned = true, want false for attached daemon")
	}
}

func TestPrepareDaemonProcessStartsWhenIPCFileIsStale(t *testing.T) {
	started := false
	deps := daemonTestDeps()
	deps.dial = func(path string) (io.Closer, error) {
		if path != "/tmp/stale.sock" {
			t.Fatalf("dial path = %q", path)
		}
		return nil, errors.New("connection refused")
	}
	deps.lookPath = func(string) (string, error) { return "/usr/local/bin/apsigner", nil }
	deps.start = func(binary, dataDir string) (*daemonProcess, error) {
		started = true
		if binary != "/usr/local/bin/apsigner" {
			t.Fatalf("binary = %q", binary)
		}
		if dataDir != "/signer" {
			t.Fatalf("dataDir = %q", dataDir)
		}
		return &daemonProcess{events: make(chan daemonEvent), done: make(chan struct{})}, nil
	}

	proc, info := prepareDaemonProcessWithDeps("/signer", "/tmp/stale.sock", "/tmp/stale.sock", true, deps)
	if !started {
		t.Fatal("start was not called")
	}
	if proc == nil {
		t.Fatal("process = nil, want process")
	}
	if info.Status != daemonStatusStarting {
		t.Fatalf("status = %s, want %s", info.Status, daemonStatusStarting)
	}
	if !info.Owned {
		t.Fatal("Owned = false, want true")
	}
}

func TestPrepareDaemonProcessReportsMissingBinary(t *testing.T) {
	deps := daemonTestDeps()
	deps.lookPath = func(string) (string, error) { return "", errors.New("missing") }
	deps.executable = func() (string, error) { return "/opt/aplane/apconsole", nil }

	proc, info := prepareDaemonProcessWithDeps("/signer", "/tmp/missing.sock", "/tmp/missing.sock", true, deps)
	if proc != nil {
		t.Fatal("process != nil, want nil")
	}
	if info.Status != daemonStatusFailed {
		t.Fatalf("status = %s, want %s", info.Status, daemonStatusFailed)
	}
	if info.Detail == "" {
		t.Fatal("Detail is empty, want startup failure detail")
	}
}

func TestPrepareDaemonProcessStartsOwnedDaemon(t *testing.T) {
	started := false
	deps := daemonTestDeps()
	deps.lookPath = func(string) (string, error) { return "/usr/local/bin/apsigner", nil }
	deps.start = func(binary, dataDir string) (*daemonProcess, error) {
		started = true
		if binary != "/usr/local/bin/apsigner" {
			t.Fatalf("binary = %q", binary)
		}
		if dataDir != "/signer" {
			t.Fatalf("dataDir = %q", dataDir)
		}
		return &daemonProcess{events: make(chan daemonEvent), done: make(chan struct{})}, nil
	}

	proc, info := prepareDaemonProcessWithDeps("/signer", "/tmp/missing.sock", "/tmp/missing.sock", true, deps)
	if !started {
		t.Fatal("start was not called")
	}
	if proc == nil {
		t.Fatal("process = nil, want process")
	}
	if info.Status != daemonStatusStarting {
		t.Fatalf("status = %s, want %s", info.Status, daemonStatusStarting)
	}
	if !info.Owned {
		t.Fatal("Owned = false, want true")
	}
}

func TestPrepareDaemonProcessStartsReadinessWatch(t *testing.T) {
	watched := false
	deps := daemonTestDeps()
	deps.lookPath = func(string) (string, error) { return "/usr/local/bin/apsigner", nil }
	started := &daemonProcess{events: make(chan daemonEvent, 1), done: make(chan struct{})}
	deps.start = func(string, string) (*daemonProcess, error) { return started, nil }
	deps.watchReady = func(dp *daemonProcess, ipcPath string) {
		watched = true
		if dp != started {
			t.Fatalf("watched process %p, want the started one %p", dp, started)
		}
		if ipcPath != "/tmp/missing.sock" {
			t.Fatalf("ipcPath = %q", ipcPath)
		}
	}

	_, info := prepareDaemonProcessWithDeps("/signer", "/tmp/missing.sock", "/tmp/missing.sock", true, deps)
	if info.Status != daemonStatusStarting {
		t.Fatalf("status = %s, want %s", info.Status, daemonStatusStarting)
	}
	if !watched {
		t.Fatal("watchReady was not called")
	}
}

func readinessTestProcess() *daemonProcess {
	return &daemonProcess{events: make(chan daemonEvent, 1), done: make(chan struct{}), ready: make(chan struct{})}
}

func requireReadyClosed(t *testing.T, dp *daemonProcess) {
	t.Helper()
	select {
	case <-dp.ready:
	default:
		t.Fatal("ready is still open after the watch ended")
	}
}

func TestWatchDaemonReadinessReportsReady(t *testing.T) {
	dp := readinessTestProcess()
	calls := 0
	dial := func(path string) (io.Closer, error) {
		if path != "/tmp/apsigner.sock" {
			t.Fatalf("path = %q", path)
		}
		calls++
		if calls < 2 {
			return nil, os.ErrNotExist
		}
		return fakeCloser{}, nil
	}

	dp.watchReadiness("/tmp/apsigner.sock", dial, time.Second, time.Millisecond)
	requireReadyClosed(t, dp)
	if calls != 2 {
		t.Fatalf("dial calls = %d, want 2", calls)
	}
	event := <-dp.events
	if event.Status != daemonStatusReady {
		t.Fatalf("status = %s, want %s", event.Status, daemonStatusReady)
	}
	if event.Detail == "" || event.Line == "" {
		t.Fatalf("event missing detail/line: %#v", event)
	}
}

func TestWatchDaemonReadinessReportsTimeout(t *testing.T) {
	dp := readinessTestProcess()

	dp.watchReadiness("/tmp/apsigner.sock",
		func(string) (io.Closer, error) { return nil, os.ErrNotExist },
		time.Millisecond,
		time.Millisecond,
	)
	requireReadyClosed(t, dp)
	event := <-dp.events
	if event.Status != daemonStatusFailed {
		t.Fatalf("status = %s, want %s", event.Status, daemonStatusFailed)
	}
	if event.Detail == "" || event.Line == "" {
		t.Fatalf("event missing detail/line: %#v", event)
	}
}

func TestWatchDaemonReadinessStopsWhenProcessDone(t *testing.T) {
	dp := readinessTestProcess()
	close(dp.done)

	dp.watchReadiness("/tmp/apsigner.sock",
		func(string) (io.Closer, error) { return nil, os.ErrNotExist },
		time.Second,
		time.Millisecond,
	)
	requireReadyClosed(t, dp)
	select {
	case event := <-dp.events:
		t.Fatalf("unexpected event: %#v", event)
	default:
	}
}

func TestDaemonModelUpdatesExitedStatus(t *testing.T) {
	m := newDaemonModel(daemonInfo{Status: daemonStatusStarting, Detail: "started"}, nil)
	m, cmd := m.Update(daemonLogMsg{event: daemonEvent{
		Status: daemonStatusExited,
		Detail: "exit status 1",
		Line:   "apsigner exited: exit status 1",
	}})
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil without events channel", cmd)
	}
	if m.status != daemonStatusExited {
		t.Fatalf("status = %s, want %s", m.status, daemonStatusExited)
	}
	want := []string{"status: exited", "exit status 1", "apsigner exited: exit status 1"}
	if got := m.lines[len(m.lines)-len(want):]; !slices.Equal(got, want) {
		t.Fatalf("last lines = %q, want %q", got, want)
	}
}

func daemonTestDeps() daemonDeps {
	return daemonDeps{
		stat:       func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		dial:       func(string) (io.Closer, error) { return nil, os.ErrNotExist },
		lookPath:   func(string) (string, error) { return "", errors.New("not found") },
		executable: func() (string, error) { return "/tmp/apconsole", nil },
		start:      func(string, string) (*daemonProcess, error) { return nil, errors.New("unexpected start") },
		watchReady: func(*daemonProcess, string) {},
	}
}

type fakeCloser struct{}

func (fakeCloser) Close() error { return nil }

// The console's startup waits on ready, and nobody reads events until the
// console runs, so ready must close before the outcome is reported.
func TestWatchDaemonReadinessReleasesStartupBeforeReporting(t *testing.T) {
	dp := &daemonProcess{events: make(chan daemonEvent), done: make(chan struct{}), ready: make(chan struct{})}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		dp.watchReadiness("/tmp/apsigner.sock", func(string) (io.Closer, error) { return fakeCloser{}, nil }, time.Second, time.Millisecond)
	}()
	select {
	case <-dp.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("ready did not close while the ready event waited for a reader")
	}
	if event := <-dp.events; event.Status != daemonStatusReady {
		t.Fatalf("status = %s, want %s", event.Status, daemonStatusReady)
	}
	<-finished
}

// A killed daemon leaves its socket file behind. The file must not count as
// a ready daemon.
func TestWatchDaemonReadinessIgnoresStaleSocketFile(t *testing.T) {
	// Unix socket paths are length-limited, so stay out of deep test dirs.
	dir, err := os.MkdirTemp("", "apc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln.SetUnlinkOnClose(false)
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stale socket file missing: %v", err)
	}

	const timeout = 300 * time.Millisecond
	dp := readinessTestProcess()
	start := time.Now()
	dp.watchReadiness(path, dialUnixSocketForDaemon, timeout, daemonReadyInterval)
	if elapsed := time.Since(start); elapsed < timeout {
		t.Fatalf("returned after %v on a stale socket file, want the %v timeout", elapsed, timeout)
	}
	if event := <-dp.events; event.Status != daemonStatusFailed {
		t.Fatalf("status = %s, want %s on a stale socket file", event.Status, daemonStatusFailed)
	}
}

// writeFakeDaemon writes a stand-in for apsigner that prints stdoutLines to
// stdout and stderrLine to stderr in one burst each, creates marker, and then
// runs tail. The output fits in the pipe buffers, so the process can exit
// before the console has read any of it.
func writeFakeDaemon(t *testing.T, stdoutLines []string, stderrLine, marker, tail string) string {
	t.Helper()
	dir := t.TempDir()
	outPath := filepath.Join(dir, "stdout.txt")
	if err := os.WriteFile(outPath, []byte(strings.Join(stdoutLines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n" +
		"cat '" + outPath + "'\n" +
		"echo '" + stderrLine + "' >&2\n" +
		": > '" + marker + "'\n" +
		tail + "\n"
	bin := filepath.Join(dir, "apsigner")
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("fake daemon never created %s", path)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// apsigner's last lines, most likely the reason it exited, must reach the
// daemon pane even when the console reads them only after the process is
// gone, and the exit event must come after them.
func TestDaemonProcessDeliversAllOutputBeforeExitEvent(t *testing.T) {
	stdoutLines := numberedLines("out", 300)
	const fatal = "fatal: store is locked"
	marker := filepath.Join(t.TempDir(), "exited")
	bin := writeFakeDaemon(t, stdoutLines, fatal, marker, "exit 3")

	dp, err := startDaemonProcess(bin, t.TempDir())
	if err != nil {
		t.Fatalf("startDaemonProcess: %v", err)
	}
	defer dp.Stop()

	// Read nothing until the process has exited, so the readers fall behind.
	waitForFile(t, marker)
	time.Sleep(200 * time.Millisecond)

	var lines []string
	var exit *daemonEvent
	deadline := time.After(5 * time.Second)
	for exit == nil {
		select {
		case event := <-dp.events:
			if event.Status == daemonStatusExited {
				exit = &event
				continue
			}
			lines = append(lines, event.Line)
		case <-deadline:
			t.Fatalf("no exit event; got %d lines", len(lines))
		}
	}
	if exit.Detail != "exit status 3" {
		t.Fatalf("exit detail = %q, want exit status 3", exit.Detail)
	}
	var gotStdout []string
	sawFatal := false
	for _, line := range lines {
		switch {
		case line == fatal:
			sawFatal = true
		case strings.HasPrefix(line, "out-"):
			gotStdout = append(gotStdout, line)
		default:
			t.Fatalf("unexpected line before exit event: %q", line)
		}
	}
	if !sawFatal {
		t.Fatalf("stderr line %q lost; got %d lines", fatal, len(lines))
	}
	if strings.Join(gotStdout, "\n") != strings.Join(stdoutLines, "\n") {
		t.Fatalf("stdout lines before exit event = %d, want all %d in order", len(gotStdout), len(stdoutLines))
	}
	select {
	case <-dp.done:
	case <-time.After(5 * time.Second):
		t.Fatal("done not closed after the exit event")
	}
}

// Once the console stops reading the daemon pane, Stop must still end a
// daemon that left more output than the event buffer holds without waiting
// out the kill timeout.
func TestDaemonProcessStopDoesNotWaitOnUnreadOutput(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "printed")
	bin := writeFakeDaemon(t, numberedLines("out", 300), "ready", marker, "exec sleep 30")

	dp, err := startDaemonProcess(bin, t.TempDir())
	if err != nil {
		t.Fatalf("startDaemonProcess: %v", err)
	}
	waitForFile(t, marker)

	start := time.Now()
	dp.Stop()
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Stop took %v, want the daemon to end on SIGTERM", elapsed)
	}
	select {
	case <-dp.done:
	default:
		t.Fatal("done not closed after Stop returned")
	}
}
