// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/aplane-algo/aplane/internal/adminipc"
)

type daemonStatus string

const (
	daemonStatusDisabled daemonStatus = "disabled"
	daemonStatusAttached daemonStatus = "attached"
	daemonStatusStarting daemonStatus = "starting"
	daemonStatusReady    daemonStatus = "ready"
	daemonStatusFailed   daemonStatus = "failed"
	daemonStatusExited   daemonStatus = "exited"
)

const (
	daemonReadyTimeout  = 5 * time.Second
	daemonReadyInterval = 100 * time.Millisecond
)

type daemonInfo struct {
	Status  daemonStatus
	Owned   bool
	DataDir string
	IPCPath string
	Binary  string
	PID     int
	Detail  string
}

func (i daemonInfo) Lines() []string {
	lines := []string{"status: " + string(i.Status)}
	if i.Detail != "" {
		lines = append(lines, i.Detail)
	}
	if i.DataDir != "" {
		lines = append(lines, "data: "+i.DataDir)
	}
	if i.IPCPath != "" {
		lines = append(lines, "IPC: "+i.IPCPath)
	}
	if i.Binary != "" {
		lines = append(lines, "binary: "+i.Binary)
	}
	if i.PID != 0 {
		lines = append(lines, fmt.Sprintf("pid: %d", i.PID))
	}
	if i.Owned {
		lines = append(lines, "ownership: apconsole will stop this daemon")
	} else {
		lines = append(lines, "ownership: external")
	}
	return lines
}

type daemonEvent struct {
	Line   string
	Status daemonStatus
	Detail string
}

type daemonProcess struct {
	cmd    *exec.Cmd
	events chan daemonEvent
	// done closes once the process has exited and all of its output has
	// been read.
	done chan struct{}
	// stopping closes when Stop begins. Nobody reads events after that, so
	// the output readers drop lines instead of waiting to deliver them.
	stopping chan struct{}
	stopOnce sync.Once
	// ready closes when the readiness watch ends: the IPC socket answered,
	// the watch timed out, or the process exited.
	ready chan struct{}
}

type daemonDeps struct {
	stat       func(string) (os.FileInfo, error)
	dial       func(string) (io.Closer, error)
	lookPath   func(string) (string, error)
	executable func() (string, error)
	start      func(binary, dataDir string) (*daemonProcess, error)
	watchReady func(dp *daemonProcess, ipcPath string)
}

func defaultDaemonDeps() daemonDeps {
	return daemonDeps{
		stat:       os.Stat,
		dial:       dialUnixSocketForDaemon,
		lookPath:   exec.LookPath,
		executable: os.Executable,
		start:      startDaemonProcess,
		watchReady: func(dp *daemonProcess, ipcPath string) {
			go dp.watchReadiness(ipcPath, dialUnixSocketForDaemon, daemonReadyTimeout, daemonReadyInterval)
		},
	}
}

func prepareDaemonProcess(dataDir, ipcPath, daemonIPCPath string, start bool) (*daemonProcess, daemonInfo) {
	return prepareDaemonProcessWithDeps(dataDir, ipcPath, daemonIPCPath, start, defaultDaemonDeps())
}

func resolveDaemonIPCPathForLifecycle(dataDir, configuredPath string, start bool) (string, error) {
	if !start {
		return "", nil
	}
	path, _, err := adminipc.ResolveDaemonPathForDataDir(dataDir, configuredPath)
	return path, err
}

func prepareDaemonProcessWithDeps(dataDir, ipcPath, daemonIPCPath string, start bool, deps daemonDeps) (*daemonProcess, daemonInfo) {
	if !start {
		return nil, daemonInfo{
			Status:  daemonStatusDisabled,
			DataDir: dataDir,
			IPCPath: ipcPath,
			Detail:  "daemon management disabled; admin pane will attach over configured IPC",
		}
	}
	if filepath.Clean(ipcPath) != filepath.Clean(daemonIPCPath) {
		return nil, daemonInfo{
			Status:  daemonStatusFailed,
			DataDir: dataDir,
			IPCPath: ipcPath,
			Detail: fmt.Sprintf(
				"daemon not started: client IPC path %s differs from the selected store's daemon path %s; use --no-start-daemon to attach through an intentional override",
				ipcPath, daemonIPCPath,
			),
		}
	}
	if conn, err := deps.dial(ipcPath); err == nil {
		_ = conn.Close()
		return nil, daemonInfo{
			Status:  daemonStatusAttached,
			DataDir: dataDir,
			IPCPath: ipcPath,
			Detail:  "attached to existing apsigner",
		}
	}

	bin, err := findApsigner(deps)
	if err != nil {
		return nil, daemonInfo{
			Status:  daemonStatusFailed,
			DataDir: dataDir,
			IPCPath: ipcPath,
			Detail:  "daemon not started: " + err.Error(),
		}
	}

	dp, err := deps.start(bin, dataDir)
	if err != nil {
		return nil, daemonInfo{
			Status:  daemonStatusFailed,
			DataDir: dataDir,
			IPCPath: ipcPath,
			Binary:  bin,
			Detail:  "daemon not started: " + err.Error(),
		}
	}

	pid := 0
	if dp.cmd != nil && dp.cmd.Process != nil {
		pid = dp.cmd.Process.Pid
	}
	deps.watchReady(dp, ipcPath)
	return dp, daemonInfo{
		Status:  daemonStatusStarting,
		Owned:   true,
		DataDir: dataDir,
		IPCPath: ipcPath,
		Binary:  bin,
		PID:     pid,
		Detail:  "started apsigner; waiting for IPC",
	}
}

func startDaemonProcess(bin, dataDir string) (*daemonProcess, error) {
	cmd := exec.Command(bin, "-d", dataDir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe failed: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe failed: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	events := make(chan daemonEvent, 128)
	dp := &daemonProcess{
		cmd:      cmd,
		events:   events,
		done:     make(chan struct{}),
		stopping: make(chan struct{}),
		ready:    make(chan struct{}),
	}
	var output sync.WaitGroup
	output.Add(2)
	go func() {
		defer output.Done()
		scanDaemonOutput(events, dp.stopping, stdout)
	}()
	go func() {
		defer output.Done()
		scanDaemonOutput(events, dp.stopping, stderr)
	}()
	go func() {
		// Wait closes the pipes once the process exits, so read them to
		// EOF first: apsigner's last lines most likely say why it exited.
		output.Wait()
		err := cmd.Wait()
		event := daemonEvent{Status: daemonStatusExited, Line: "apsigner exited"}
		if err != nil {
			event.Detail = err.Error()
			event.Line = "apsigner exited: " + err.Error()
		}
		// The exit event follows every output line. Once Stop has begun
		// nobody reads it, and closing done below carries the exit.
		sendDaemonEvent(events, dp.stopping, event)
		close(dp.done)
	}()
	return dp, nil
}

func dialUnixSocketForDaemon(path string) (io.Closer, error) {
	return net.Dial("unix", path)
}

func findApsigner(deps daemonDeps) (string, error) {
	if path, err := deps.lookPath("apsigner"); err == nil {
		return path, nil
	}
	self, err := deps.executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(self), "apsigner")
		if st, statErr := deps.stat(candidate); statErr == nil && !st.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("apsigner binary not found in PATH or next to apconsole")
}

// scanDaemonOutput reads r to EOF, sending each line as an event until
// stopping closes and dropping lines after that.
func scanDaemonOutput(events chan<- daemonEvent, stopping <-chan struct{}, r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		sendDaemonEvent(events, stopping, daemonEvent{Line: scanner.Text()})
	}
	if err := scanner.Err(); err != nil {
		sendDaemonEvent(events, stopping, daemonEvent{Line: "log stream error: " + err.Error()})
		// Keep draining, so apsigner never blocks writing to a full pipe.
		_, _ = io.Copy(io.Discard, r)
	}
}

// watchReadiness dials the daemon's IPC socket until it accepts a
// connection, the process exits, or timeout passes, then closes p.ready and
// reports the outcome on p.events. It dials rather than checking that the
// socket file exists: a daemon that was killed leaves its socket file behind,
// and that file says nothing about the new daemon.
func (p *daemonProcess) watchReadiness(ipcPath string, dial func(string) (io.Closer, error), timeout, interval time.Duration) {
	event, exited := awaitDaemonIPC(p.done, ipcPath, dial, timeout, interval)
	// Release the console's startup first: nobody reads events until the
	// console runs, so the report below may wait.
	close(p.ready)
	if !exited {
		sendDaemonEvent(p.events, p.done, event)
	}
}

// awaitDaemonIPC polls ipcPath for watchReadiness. It returns the ready or
// timeout event to report, or exited when done closed first.
func awaitDaemonIPC(done <-chan struct{}, ipcPath string, dial func(string) (io.Closer, error), timeout, interval time.Duration) (event daemonEvent, exited bool) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if conn, err := dial(ipcPath); err == nil {
			_ = conn.Close()
			return daemonEvent{
				Status: daemonStatusReady,
				Detail: "apsigner IPC ready",
				Line:   "apsigner IPC ready: " + ipcPath,
			}, false
		}

		select {
		case <-done:
			return daemonEvent{}, true
		case <-ticker.C:
		case <-deadline.C:
			return daemonEvent{
				Status: daemonStatusFailed,
				Detail: "timed out waiting for apsigner IPC",
				Line:   "apsigner readiness timeout: " + ipcPath,
			}, false
		}
	}
}

func sendDaemonEvent(events chan<- daemonEvent, done <-chan struct{}, event daemonEvent) {
	if done == nil {
		events <- event
		return
	}
	select {
	case <-done:
	case events <- event:
	}
}

func (p *daemonProcess) Stop() {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	if p.stopping != nil {
		p.stopOnce.Do(func() { close(p.stopping) })
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
	}
}
