// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"syscall"
	"testing"
	"time"
)

// During startup a signal stops the daemon this console started and exits
// with the signal's status; once the TUI runs it is left to the TUI, and
// during shutdown it is absorbed so the cleanup finishes.
func TestConsoleSignalsByPhase(t *testing.T) {
	for _, tc := range []struct {
		phase    int32
		sig      os.Signal
		stopped  bool
		exitCode int
	}{
		{consoleStarting, os.Interrupt, true, 130},
		{consoleStarting, syscall.SIGTERM, true, 143},
		{consoleRunning, os.Interrupt, false, -1},
		{consoleShuttingDown, os.Interrupt, false, -1},
		{consoleShuttingDown, syscall.SIGTERM, false, -1},
	} {
		stopped, code := false, -1
		handleConsoleSignal(tc.phase, tc.sig, func() { stopped = true }, func(c int) { code = c })
		if stopped != tc.stopped || code != tc.exitCode {
			t.Errorf("phase %d, %v: stopped=%v exit=%d; want stopped=%v exit=%d", tc.phase, tc.sig, stopped, code, tc.stopped, tc.exitCode)
		}
	}
	// No daemon to stop: startup still exits.
	code := -1
	handleConsoleSignal(consoleStarting, os.Interrupt, nil, func(c int) { code = c })
	if code != 130 {
		t.Fatalf("exit without a daemon = %d, want 130", code)
	}
}

// startConsole moves the phase on, so a signal after the TUI returns is
// absorbed rather than cutting the cleanup short.
func TestStartConsoleLeavesTheShutdownPhase(t *testing.T) {
	t.Cleanup(func() { consolePhase.Store(consoleStarting) })
	consolePhase.Store(consoleStarting)
	stdio := swapConsoleStdio(t)
	dp := startOwnedFakeDaemon(t)
	codes := make(chan int, 1)
	go func() {
		codes <- startConsole(panickingConnector{}, t.TempDir(), "cosigner", nil, nil, false, dp, ownedDaemonModel(dp))
	}()
	select {
	case <-codes:
	case <-time.After(10 * time.Second):
		t.Fatal("console did not return")
	}
	assertConsoleCleanedUp(t, stdio, dp)
	if got := consolePhase.Load(); got != consoleShuttingDown {
		t.Fatalf("phase after startConsole = %d, want shutting down (%d)", got, consoleShuttingDown)
	}
}
