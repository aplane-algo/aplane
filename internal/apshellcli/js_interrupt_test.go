// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/config"
)

func newJSInterruptSession(t *testing.T) *Session {
	t.Helper()
	session, err := NewSession("testnet", config.DefaultConfig(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	t.Cleanup(session.Shutdown)
	return session
}

// requireShellFree checks that the command released the shell's runtime
// lock, which completion and the signer poller also take.
func requireShellFree(t *testing.T, state *REPLState) {
	t.Helper()
	if !state.runtimeMu.TryLock() {
		t.Fatal("runtime lock still held after the interrupted script")
	}
	state.runtimeMu.Unlock()
}

// apconsole's Ctrl-C: Session.Cancel stops an endless script, the session's
// locks are free again, and the next script runs.
func TestSessionCancelInterruptsAnEndlessScript(t *testing.T) {
	session := newJSInterruptSession(t)

	type outcome struct {
		output string
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		output, _, err := session.ExecuteLineCaptured("js while (true) {}")
		done <- outcome{output, err}
	}()

	// Let the loop start, so the cancel interrupts a running script.
	time.Sleep(50 * time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for !session.Cancel() {
		if time.Now().After(deadline) {
			t.Fatal("the script never became cancellable")
		}
		time.Sleep(5 * time.Millisecond)
	}

	select {
	case got := <-done:
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("ExecuteLineCaptured() error = %v, want context.Canceled", got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the endless script was not interrupted")
	}
	requireShellFree(t, session.state)

	output, _, err := session.ExecuteLineCaptured("js 40 + 2")
	if err != nil {
		t.Fatalf("next script error = %v", err)
	}
	if !strings.Contains(output, "42") {
		t.Fatalf("next script output = %q, want 42", output)
	}
}

// The REPL's Ctrl-C: SIGINT during a command cancels it, an endless script
// stops, and the next script runs.
func TestREPLInterruptStopsAnEndlessScript(t *testing.T) {
	session := newJSInterruptSession(t)
	state := session.state

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- state.executeCommandWithInterrupt(Command{Name: "js", Args: []string{"while", "(true)", "{}"}, RawArgs: "while (true) {}"}, sigCh)
	}()
	// The command drops a signal that arrived before it started, so keep
	// pressing Ctrl-C until it stops.
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
wait:
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("executeCommandWithInterrupt() error = %v, want the interrupt reported as handled", err)
			}
			break wait
		case <-tick.C:
			select {
			case sigCh <- syscall.SIGINT:
			default:
			}
		case <-deadline:
			t.Fatal("Ctrl-C did not stop the endless script")
		}
	}
	requireShellFree(t, state)

	if err := state.executeCommandWithInterrupt(Command{Name: "js", Args: []string{"1"}, RawArgs: "1"}, sigCh); err != nil {
		t.Fatalf("next script error = %v", err)
	}
}

// captureJSExecution, which the MCP js tool calls, runs the script under the
// context it is given: cancelling that context stops an endless script and
// the next call runs. This is not MCP cancellation: the stdio server's tool
// contexts are never cancelled (see the js tool in docs/ARCH_SHELL.md).
func TestCaptureJSExecutionStopsWhenItsContextIsCancelled(t *testing.T) {
	session := newJSInterruptSession(t)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	done := make(chan error, 1)
	go func() {
		_, err := captureJSExecution(ctx, session.state, `print("started"); while (true) {}`)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("captureJSExecution() error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the endless script was not interrupted")
	}

	result := mcpJSExecutionResult(context.Background(), session.state, "1 + 1")
	if result.IsError {
		t.Fatalf("next js tool call failed: %#v", result.Content)
	}
}
