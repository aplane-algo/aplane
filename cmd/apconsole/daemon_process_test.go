// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
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
	deps.stat = func(string) (os.FileInfo, error) {
		t.Fatal("mismatched path was inspected for attachment")
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
	deps.stat = func(path string) (os.FileInfo, error) {
		if path == "/tmp/apsigner.sock" {
			return fakeFileInfo{}, nil
		}
		return nil, os.ErrNotExist
	}
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
	deps.stat = func(path string) (os.FileInfo, error) {
		if path == "/tmp/stale.sock" {
			return fakeFileInfo{}, nil
		}
		return nil, os.ErrNotExist
	}
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
	deps.stat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }

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
	deps.stat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
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
	deps.stat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	deps.lookPath = func(string) (string, error) { return "/usr/local/bin/apsigner", nil }
	deps.start = func(string, string) (*daemonProcess, error) {
		return &daemonProcess{events: make(chan daemonEvent, 1), done: make(chan struct{})}, nil
	}
	deps.watchReady = func(events chan<- daemonEvent, done <-chan struct{}, ipcPath string) {
		watched = true
		if events == nil {
			t.Fatal("events = nil")
		}
		if done == nil {
			t.Fatal("done = nil")
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

func TestWatchDaemonReadinessReportsReady(t *testing.T) {
	events := make(chan daemonEvent, 1)
	done := make(chan struct{})
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

	watchDaemonReadiness(events, done, "/tmp/apsigner.sock", dial, time.Second, time.Millisecond)
	event := <-events
	if event.Status != daemonStatusReady {
		t.Fatalf("status = %s, want %s", event.Status, daemonStatusReady)
	}
	if event.Detail == "" || event.Line == "" {
		t.Fatalf("event missing detail/line: %#v", event)
	}
}

func TestWatchDaemonReadinessReportsTimeout(t *testing.T) {
	events := make(chan daemonEvent, 1)
	done := make(chan struct{})

	watchDaemonReadiness(events, done, "/tmp/apsigner.sock",
		func(string) (io.Closer, error) { return nil, os.ErrNotExist },
		time.Millisecond,
		time.Millisecond,
	)
	event := <-events
	if event.Status != daemonStatusFailed {
		t.Fatalf("status = %s, want %s", event.Status, daemonStatusFailed)
	}
	if event.Detail == "" || event.Line == "" {
		t.Fatalf("event missing detail/line: %#v", event)
	}
}

func TestWatchDaemonReadinessStopsWhenProcessDone(t *testing.T) {
	events := make(chan daemonEvent, 1)
	done := make(chan struct{})
	close(done)

	watchDaemonReadiness(events, done, "/tmp/apsigner.sock",
		func(string) (io.Closer, error) { return nil, os.ErrNotExist },
		time.Millisecond,
		time.Millisecond,
	)
	select {
	case event := <-events:
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
	if m.detail != "exit status 1" {
		t.Fatalf("detail = %q", m.detail)
	}
}

func daemonTestDeps() daemonDeps {
	return daemonDeps{
		stat:       func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		dial:       func(string) (io.Closer, error) { return nil, os.ErrNotExist },
		lookPath:   func(string) (string, error) { return "", errors.New("not found") },
		executable: func() (string, error) { return "/tmp/apconsole", nil },
		start:      func(string, string) (*daemonProcess, error) { return nil, errors.New("unexpected start") },
		watchReady: func(chan<- daemonEvent, <-chan struct{}, string) {},
	}
}

type fakeFileInfo struct{}

func (fakeFileInfo) Name() string       { return "apsigner.sock" }
func (fakeFileInfo) Size() int64        { return 0 }
func (fakeFileInfo) Mode() os.FileMode  { return 0600 }
func (fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (fakeFileInfo) IsDir() bool        { return false }
func (fakeFileInfo) Sys() any           { return nil }

type fakeCloser struct{}

func (fakeCloser) Close() error { return nil }
