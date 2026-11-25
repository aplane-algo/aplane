// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package manager

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
)

// scriptPlugin is a running instance whose process runs script, both its output
// pipes read as a real plugin's are.
func scriptPlugin(t *testing.T, script string) *Instance {
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
	return newInstance(testPlugin("script"), cmd, stdin, stdout, stderr, nil)
}

// stopWithin stops inst with grace and returns how long that took.
func stopWithin(t *testing.T, inst *Instance, grace, limit time.Duration) time.Duration {
	t.Helper()
	begin := time.Now()
	_ = within(t, limit, "stop", func() error {
		inst.stop(grace)
		return nil
	})
	return time.Since(begin)
}

// What a plugin says while it exits is read to the end: its last stderr line is
// logged by the time stop returns, and its writes don't fail, whichever of its
// outputs ends first.
func TestStopReadsAPluginsLastWords(t *testing.T) {
	for name, tt := range map[string]struct {
		script string
		lines  []string
	}{
		"both outputs": {`cat >/dev/null; sleep 0.2; echo '{"jsonrpc":"2.0","method":"bye"}' || exit 3; echo 'last words' >&2 || exit 4`,
			[]string{"[plugin script stderr] last words"}},
		"stderr, after closing stdout": {`cat >/dev/null; exec >&-; sleep 0.2; echo 'last words' >&2 || exit 4`,
			[]string{"[plugin script stderr] last words"}},
		"stdout, after closing stderr": {`cat >/dev/null; exec 2>&-; sleep 0.2; echo '{"jsonrpc":"2.0","method":"bye"}' || exit 3`, nil},
	} {
		t.Run(name, func(t *testing.T) {
			sink := installLogs(t, slog.LevelInfo)
			inst := scriptPlugin(t, tt.script)
			stopWithin(t, inst, 5*time.Second, 4*time.Second)
			if state := inst.Process.ProcessState; !state.Success() {
				t.Fatalf("plugin ended with %v, want a clean exit", state)
			}
			assertLines(t, sink.lines(), tt.lines)
		})
	}
}

// A plugin that outlasts the grace is killed, and one whose output never ends
// doesn't hold stop up beyond it.
func TestStopIsBoundedByTheGrace(t *testing.T) {
	const grace = 300 * time.Millisecond
	// A child is left running when its plugin is killed, so it is short-lived,
	// though it outlasts the limit on stop.
	for name, tt := range map[string]struct {
		script string
		// graceUsed is whether the plugin must get all of the grace.
		graceUsed bool
	}{
		"ignores end of input":                    {"exec sleep 30", true},
		"keeps printing":                          {"while :; do echo; echo >&2; sleep 0.05; done", true},
		"closes its output and hangs":             {"cat >/dev/null; exec >&- 2>&-; exec sleep 30", true},
		"hangs, a child holding its stdout":       {"sleep 8 2>/dev/null & exec sleep 30", true},
		"hangs, a child holding its stderr":       {"sleep 8 >/dev/null & exec sleep 30", true},
		"exits, a child holding both its outputs": {"sleep 8 & cat >/dev/null", false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			inst := scriptPlugin(t, tt.script)
			took := stopWithin(t, inst, grace, 5*time.Second)
			if tt.graceUsed && took < grace {
				t.Fatalf("stop took %v, less than the %v grace", took, grace)
			}
			if processRunning(inst) {
				t.Fatal("the plugin process is still running")
			}
		})
	}
}

// A plugin that exits when its input ends is not held for the grace.
func TestStopDoesNotWaitOutTheGraceOfAPluginThatExits(t *testing.T) {
	inst := scriptPlugin(t, "cat >/dev/null")
	if took := stopWithin(t, inst, 30*time.Second, 5*time.Second); took > 3*time.Second {
		t.Fatalf("stop took %v", took)
	}
}

// The client gives up on an overlong line, after which nothing reads stdout. Its
// pipe is closed then, or a plugin still writing to it would hang until killed.
func TestStopClosesStdoutOnceNothingReadsIt(t *testing.T) {
	inst := scriptPlugin(t, "while :; do printf %01024d 0; done")
	select {
	case <-inst.stdoutDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the client never gave up on the overlong line")
	}
	stopWithin(t, inst, 30*time.Second, 5*time.Second)
}

// Cancelling a command or signing call that is starting its plugin ends the
// initialize call and stops the plugin within abandonGrace.
func TestCancelReachesAPluginThatHangsInInitialize(t *testing.T) {
	for name, call := range map[string]func(context.Context, *Manager) error{
		"execute": func(ctx context.Context, m *Manager) error {
			_, err := m.ExecuteCommand(ctx, "script", "work", nil, jsonrpc.Context{})
			return err
		},
		"signTransactions": func(ctx context.Context, m *Manager) error {
			_, err := m.SignTransactions(ctx, "script", jsonrpc.SignTransactionsParams{})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := NewManagerWithDataDir("")
			m.SetCachedPluginsForTest([]*discovery.Plugin{testPlugin("script")})
			inst := scriptPlugin(t, "exec sleep 30")
			m.startPluginInstanceHook = func(*discovery.Plugin) (*Instance, error) { return inst, nil }
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(100*time.Millisecond, cancel)

			begin := time.Now()
			err := within(t, 5*time.Second, name, func() error { return call(ctx, m) })
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, want the cancellation", err)
			}
			if took := time.Since(begin); took > 100*time.Millisecond+stderrDrainWait+abandonGrace+time.Second {
				t.Fatalf("the cancel took %v, want about the %v grace", took, abandonGrace)
			}
			if processRunning(inst) {
				t.Fatal("the plugin process is still running")
			}
			if running := m.GetRunningPlugins(); len(running) != 0 {
				t.Fatalf("running plugins = %v, want none", running)
			}
		})
	}
}

// A plugin that fails to initialize without a cancel gets Stop's longer grace.
func TestFailedInitializeGetsTheLongerGrace(t *testing.T) {
	exited := filepath.Join(t.TempDir(), "exited")
	m := NewManagerWithDataDir("")
	m.SetCachedPluginsForTest([]*discovery.Plugin{testPlugin("script")})
	m.startPluginInstanceHook = func(*discovery.Plugin) (*Instance, error) {
		return scriptPlugin(t, "cat >/dev/null; sleep 1.5; touch "+exited), nil
	}
	m.initializePluginHook = func(context.Context, *Instance, runtimeConfig) error { return errors.New("no") }
	if _, err := m.StartPlugin(context.Background(), "script"); err == nil {
		t.Fatal("StartPlugin() succeeded")
	}
	if _, err := os.Stat(exited); err != nil {
		t.Fatalf("the plugin was killed before it could finish exiting: %v", err)
	}
}

// A plugin that fails is stopped before its hidden stderr is reported, so the
// report has what it said while exiting.
func TestFailedPluginReportsWhatItSaidWhileStopping(t *testing.T) {
	const script = `echo working >&2; cat >/dev/null; echo 'could not save state' >&2`
	for name, run := range map[string]func(*Manager) error{
		"failed initialize": func(m *Manager) error {
			m.initializePluginHook = func(context.Context, *Instance, runtimeConfig) error { return errors.New("no") }
			_, err := m.StartPlugin(context.Background(), "script")
			return err
		},
		"cancelled command": func(m *Manager) error {
			m.initializePluginHook = func(context.Context, *Instance, runtimeConfig) error { return nil }
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(100*time.Millisecond, cancel)
			_, err := m.ExecuteCommand(ctx, "script", "work", nil, jsonrpc.Context{})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			sink := installLogs(t, slog.LevelWarn)
			m := NewManagerWithDataDir("")
			m.SetCachedPluginsForTest([]*discovery.Plugin{testPlugin("script")})
			m.startPluginInstanceHook = func(*discovery.Plugin) (*Instance, error) { return scriptPlugin(t, script), nil }
			if err := run(m); err == nil {
				t.Fatal("expected the call to fail")
			}
			assertLines(t, sink.lines(), []string{
				"[plugin script stderr] warning: working",
				"[plugin script stderr] warning: could not save state",
			})
		})
	}
}

// A call another goroutine has in flight ends as the stop begins, not when the
// plugin has gone.
func TestStopEndsACallInFlightAtOnce(t *testing.T) {
	inst := scriptPlugin(t, "exec sleep 30")
	callEnded := make(chan error, 1)
	go func() {
		callEnded <- inst.Client.CallContext(context.Background(), jsonrpc.MethodExecute, jsonrpc.ExecuteParams{}, nil, 30*time.Second)
	}()
	time.Sleep(50 * time.Millisecond)
	stopped := make(chan struct{})
	go func() {
		inst.stop(time.Second)
		close(stopped)
	}()
	select {
	case err := <-callEnded:
		if !errors.Is(err, jsonrpc.ErrConnectionClosed) {
			t.Fatalf("call error = %v, want %v", err, jsonrpc.ErrConnectionClosed)
		}
	case <-stopped:
		t.Fatal("the call was still in flight when the plugin had been stopped")
	}
	<-stopped
}

// An ended context leaves a running plugin alone.
func TestCancelledCallLeavesARunningPluginAlone(t *testing.T) {
	m := NewManagerWithDataDir("")
	inst := scriptPlugin(t, "cat >/dev/null")
	m.instances["script"] = inst
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.ExecuteCommand(ctx, "script", "work", nil, jsonrpc.Context{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("ExecuteCommand() error = %v, want the cancellation", err)
	}
	if _, err := m.SignTransactions(ctx, "script", jsonrpc.SignTransactionsParams{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("SignTransactions() error = %v, want the cancellation", err)
	}
	if running := m.GetRunningPlugins(); len(running) != 1 || !processRunning(inst) {
		t.Fatalf("running plugins = %v, process running = %v; want the plugin left alone", running, processRunning(inst))
	}
	inst.Stop()
}
