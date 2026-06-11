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
	"syscall"
	"time"
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
	done   chan struct{}
}

type daemonDeps struct {
	stat       func(string) (os.FileInfo, error)
	dial       func(string) (io.Closer, error)
	lookPath   func(string) (string, error)
	executable func() (string, error)
	start      func(binary, dataDir string) (*daemonProcess, error)
	watchReady func(events chan<- daemonEvent, done <-chan struct{}, ipcPath string)
}

func defaultDaemonDeps() daemonDeps {
	return daemonDeps{
		stat:       os.Stat,
		dial:       dialUnixSocketForDaemon,
		lookPath:   exec.LookPath,
		executable: os.Executable,
		start:      startDaemonProcess,
		watchReady: func(events chan<- daemonEvent, done <-chan struct{}, ipcPath string) {
			go watchDaemonReadiness(events, done, ipcPath, dialUnixSocketForDaemon, daemonReadyTimeout, daemonReadyInterval)
		},
	}
}

func prepareDaemonProcess(dataDir, ipcPath string, start bool) (*daemonProcess, daemonInfo) {
	return prepareDaemonProcessWithDeps(dataDir, ipcPath, start, defaultDaemonDeps())
}

func prepareDaemonProcessWithDeps(dataDir, ipcPath string, start bool, deps daemonDeps) (*daemonProcess, daemonInfo) {
	if !start {
		return nil, daemonInfo{
			Status:  daemonStatusDisabled,
			DataDir: dataDir,
			IPCPath: ipcPath,
			Detail:  "daemon management disabled; admin pane will attach over configured IPC/SSH",
		}
	}
	if ipcPath != "" {
		if _, err := deps.stat(ipcPath); err == nil {
			if conn, dialErr := deps.dial(ipcPath); dialErr == nil {
				_ = conn.Close()
				return nil, daemonInfo{
					Status:  daemonStatusAttached,
					DataDir: dataDir,
					IPCPath: ipcPath,
					Detail:  "attached to existing apsigner",
				}
			}
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
	if dp != nil && dp.cmd != nil && dp.cmd.Process != nil {
		pid = dp.cmd.Process.Pid
	}
	if dp != nil && dp.events != nil && ipcPath != "" && deps.watchReady != nil {
		deps.watchReady(dp.events, dp.done, ipcPath)
	}
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
	dp := &daemonProcess{cmd: cmd, events: events, done: make(chan struct{})}
	go scanDaemonOutput(events, dp.done, stdout)
	go scanDaemonOutput(events, dp.done, stderr)
	go func() {
		err := cmd.Wait()
		event := daemonEvent{Status: daemonStatusExited, Line: "apsigner exited"}
		if err != nil {
			event.Detail = err.Error()
			event.Line = "apsigner exited: " + err.Error()
		}
		// Never block Stop on an unread events channel: if the buffer is
		// full nobody is draining it, and closing done below carries the
		// exit signal.
		select {
		case events <- event:
		default:
		}
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

func scanDaemonOutput(events chan<- daemonEvent, done <-chan struct{}, r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		sendDaemonEvent(events, done, daemonEvent{Line: scanner.Text()})
	}
	if err := scanner.Err(); err != nil {
		sendDaemonEvent(events, done, daemonEvent{Line: "log stream error: " + err.Error()})
	}
}

func watchDaemonReadiness(events chan<- daemonEvent, done <-chan struct{}, ipcPath string, dial func(string) (io.Closer, error), timeout, interval time.Duration) {
	if events == nil || ipcPath == "" {
		return
	}
	if dial == nil {
		dial = dialUnixSocketForDaemon
	}
	if timeout <= 0 {
		timeout = daemonReadyTimeout
	}
	if interval <= 0 {
		interval = daemonReadyInterval
	}

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if conn, err := dial(ipcPath); err == nil {
			_ = conn.Close()
			sendDaemonEvent(events, done, daemonEvent{
				Status: daemonStatusReady,
				Detail: "apsigner IPC ready",
				Line:   "apsigner IPC ready: " + ipcPath,
			})
			return
		}

		select {
		case <-done:
			return
		case <-ticker.C:
		case <-deadline.C:
			sendDaemonEvent(events, done, daemonEvent{
				Status: daemonStatusFailed,
				Detail: "timed out waiting for apsigner IPC",
				Line:   "apsigner readiness timeout: " + ipcPath,
			})
			return
		}
	}
}

// waitForDaemonReady blocks until the IPC socket appears, the daemon process
// exits, or the timeout elapses. The independent goroutine in watchDaemonReadiness
// still owns event emission — this just delays callers (shell/signer connect)
// past the daemon startup window so first-attempt connections succeed.
func waitForDaemonReady(ipcPath string, dp *daemonProcess, timeout time.Duration) {
	if ipcPath == "" || timeout <= 0 {
		return
	}
	var done <-chan struct{}
	if dp != nil {
		done = dp.done
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(daemonReadyInterval)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(ipcPath); err == nil {
			return
		}
		select {
		case <-deadline.C:
			return
		case <-done:
			return
		case <-ticker.C:
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
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
	}
}
