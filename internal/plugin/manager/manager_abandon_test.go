// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package manager

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/plugin/manifest"
)

// silentPlugin is an instance whose process runs script, with its stdin the
// instance's, and whose JSON-RPC peer reads each request and never answers.
// asked is closed at the first request.
func silentPlugin(t *testing.T, script string) (inst *Instance, asked chan struct{}) {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
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
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	serverToClientReader, serverToClientWriter := io.Pipe()
	clientToServerReader, clientToServerWriter := io.Pipe()
	t.Cleanup(func() {
		_ = serverToClientWriter.Close()
		_ = clientToServerReader.Close()
	})
	inst = NewTestInstanceForHooks(&discovery.Plugin{Manifest: &manifest.Manifest{Name: "silent", Timeout: 30}},
		cmd, jsonrpc.NewClient(serverToClientReader, clientToServerWriter), stdin, stdout, stderr, time.Now())
	inst.Client.Start()
	asked = make(chan struct{})
	go func() {
		var req jsonrpc.Request
		if err := json.NewDecoder(clientToServerReader).Decode(&req); err == nil {
			close(asked)
		}
	}()
	return inst, asked
}

// abandon runs a command on inst that is cancelled once the plugin has it,
// and returns how long the call took.
func abandon(t *testing.T, inst *Instance, asked chan struct{}) time.Duration {
	t.Helper()
	m := NewManagerWithDataDir("")
	m.instances["silent"] = inst
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-asked
		cancel()
	}()
	begin := time.Now()
	if _, err := m.ExecuteCommand(ctx, "silent", "work", nil, jsonrpc.Context{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("ExecuteCommand() error = %v, want the call abandoned", err)
	}
	if running := m.GetRunningPlugins(); len(running) != 0 {
		t.Fatalf("running plugins = %v, want the abandoned instance gone", running)
	}
	return time.Since(begin)
}

// A plugin whose call was abandoned has its stdin closed and a moment to
// exit on its own, as a stateful plugin finishing its own state needs.
func TestAbandonedPluginGetsAGraceToExit(t *testing.T) {
	exited := filepath.Join(t.TempDir(), "exited")
	inst, asked := silentPlugin(t, "cat >/dev/null; sleep 0.2; touch "+exited)
	abandon(t, inst, asked)
	if _, err := os.Stat(exited); err != nil {
		t.Fatalf("the plugin was killed before it could finish exiting: %v", err)
	}
}

// The grace is short: a plugin that does not exit is killed after it, so a
// cancel still ends promptly.
func TestAbandonedPluginThatDoesNotExitIsKilledAfterTheGrace(t *testing.T) {
	inst, asked := silentPlugin(t, "exec sleep 30")
	if took := abandon(t, inst, asked); took > abandonGrace+time.Second {
		t.Fatalf("the abandoned call took %v, want about the %v grace", took, abandonGrace)
	}
}

// A call whose context has already ended starts no plugin process.
func TestCancelledCallStartsNoPlugin(t *testing.T) {
	m := NewManagerWithDataDir("")
	m.SetCachedPluginsForTest([]*discovery.Plugin{{Manifest: &manifest.Manifest{Name: "silent", Timeout: 30}}})
	starts := 0
	m.SetTestHooks(TestHooks{StartPluginInstance: func(*discovery.Plugin) (*Instance, error) {
		starts++
		return nil, errors.New("test hook: no process")
	}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := m.ExecuteCommand(ctx, "silent", "work", nil, jsonrpc.Context{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("ExecuteCommand() error = %v, want the cancellation", err)
	}
	if _, err := m.SignTransactions(ctx, "silent", jsonrpc.SignTransactionsParams{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("SignTransactions() error = %v, want the cancellation", err)
	}
	if starts != 0 {
		t.Fatalf("a cancelled call started the plugin %d time(s)", starts)
	}
}
