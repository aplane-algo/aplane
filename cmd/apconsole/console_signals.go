// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
)

// The console's phases, as its signal watcher sees them.
const (
	// consoleStarting: before the TUI runs. An interrupt or termination
	// stops the apsigner this console started and exits, rather than
	// killing the console and leaving the child running.
	consoleStarting int32 = iota
	// consoleRunning: the TUI owns signals (Bubble Tea turns them into a
	// quit), so the watcher does nothing.
	consoleRunning
	// consoleShuttingDown: the TUI has returned and the deferred cleanup is
	// stopping the child. Another signal must not cut that short, so the
	// watcher absorbs it.
	consoleShuttingDown
)

// consolePhase is read by the signal watcher; startConsole moves it on.
var consolePhase atomic.Int32

// consoleSignalExitCode is the conventional exit status for a signal.
func consoleSignalExitCode(sig os.Signal) int {
	if sig == syscall.SIGTERM {
		return 128 + int(syscall.SIGTERM)
	}
	return 128 + int(syscall.SIGINT)
}

// handleConsoleSignal decides what a signal does in phase: during startup it
// stops the owned daemon (if any) and exits with the signal's status; later
// it is left to the TUI or absorbed.
func handleConsoleSignal(phase int32, sig os.Signal, stopDaemon func(), exit func(int)) {
	if phase != consoleStarting {
		return
	}
	if stopDaemon != nil {
		stopDaemon()
	}
	exit(consoleSignalExitCode(sig))
}

// watchConsoleSignals keeps SIGINT and SIGTERM from killing the console
// outright for its whole life, so an owned apsigner is never left behind by
// one; handleConsoleSignal decides what each does.
func watchConsoleSignals(daemon *daemonProcess) {
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	var stop func()
	if daemon != nil {
		stop = daemon.Stop
	}
	go func() {
		for sig := range signals {
			handleConsoleSignal(consolePhase.Load(), sig, stop, exitConsole)
		}
	}()
}
