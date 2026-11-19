// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package manager

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/plugin/manifest"
)

// enteredWriter reports, by closing entered, the first time a write to w
// begins.
type enteredWriter struct {
	w       io.Writer
	once    sync.Once
	entered chan struct{}
}

func (e *enteredWriter) Write(p []byte) (int, error) {
	e.once.Do(func() { close(e.entered) })
	return e.w.Write(p)
}

// unreadingPlugin is a running instance, registered as "unreading" with the
// given manifest timeout, whose process never reads its stdin. It prints
// blank lines, which the client skips, so it dies of SIGPIPE soon after the
// host closes its stdout. entered closes when the first write to its stdin
// begins.
func unreadingPlugin(t *testing.T, m *Manager, timeoutSeconds int) (entered chan struct{}) {
	t.Helper()
	cmd := exec.Command("sh", "-c", "while :; do echo; sleep 0.05; done")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Killing the process unblocks a write still stuck in its stdin.
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	entered = make(chan struct{})
	client := jsonrpc.NewClient(stdout, &enteredWriter{w: stdin, entered: entered})
	inst := NewTestInstanceForHooks(&discovery.Plugin{Manifest: &manifest.Manifest{Name: "unreading", Timeout: timeoutSeconds}},
		cmd, client, stdin, stdout, stderr, time.Now())
	client.Start()
	m.instances["unreading"] = inst
	return entered
}

// bigContext is larger than any pipe buffer, so its request cannot be
// written unless the plugin reads.
func bigContext() jsonrpc.Context {
	return jsonrpc.Context{AddressMap: map[string]string{"x": strings.Repeat("a", 256*1024)}}
}

// within runs fn and fails the test if it has not returned after limit.
func within(t *testing.T, limit time.Duration, what string, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(limit):
		t.Fatalf("%s still blocked after %v", what, limit)
		return nil
	}
}

// A plugin that stops reading its input fails the command at the manifest
// timeout, and is stopped.
func TestCommandToAPluginThatStopsReadingTimesOut(t *testing.T) {
	m := NewManagerWithDataDir("")
	unreadingPlugin(t, m, 1)
	err := within(t, 5*time.Second, "ExecuteCommand", func() error {
		_, err := m.ExecuteCommand(context.Background(), "unreading", "work", nil, bigContext())
		return err
	})
	if !errors.Is(err, jsonrpc.ErrWriteStalled) {
		t.Fatalf("ExecuteCommand() error = %v, want %v", err, jsonrpc.ErrWriteStalled)
	}
	if running := m.GetRunningPlugins(); len(running) != 0 {
		t.Fatalf("running plugins = %v, want the plugin stopped", running)
	}
}

// Cancelling the command reaches a plugin that stops reading its input.
func TestCancelReachesAPluginThatStopsReading(t *testing.T) {
	m := NewManagerWithDataDir("")
	entered := unreadingPlugin(t, m, 30)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-entered
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	err := within(t, 3*time.Second, "ExecuteCommand", func() error {
		_, err := m.ExecuteCommand(ctx, "unreading", "work", nil, bigContext())
		return err
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ExecuteCommand() error = %v, want the cancellation", err)
	}
	if running := m.GetRunningPlugins(); len(running) != 0 {
		t.Fatalf("running plugins = %v, want the plugin stopped", running)
	}
}

// StopAll does not wait behind a request the plugin is not reading, and the
// command that sent it ends with the stop.
func TestStopAllDoesNotWaitForAStalledWrite(t *testing.T) {
	m := NewManagerWithDataDir("")
	entered := unreadingPlugin(t, m, 30)
	commandErr := make(chan error, 1)
	go func() {
		_, err := m.ExecuteCommand(context.Background(), "unreading", "work", nil, bigContext())
		commandErr <- err
	}()
	<-entered
	_ = within(t, 2*time.Second, "StopAll", func() error {
		m.StopAll()
		return nil
	})
	select {
	case err := <-commandErr:
		if err == nil {
			t.Fatal("ExecuteCommand() = nil, want it ended by the stop")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ExecuteCommand() still blocked after the plugin was stopped")
	}
}
