// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// consoleStdio stands in for the terminal while a test runs the console:
// stdin is a pipe already at EOF, and stdout and stderr are files. Bubble Tea
// closes its input reader without waiting for the read loop when the program
// is killed, which the race detector reports while a read is in progress; at
// EOF the read loop has ended before the program is.
type consoleStdio struct {
	stdin  *os.File
	stdout *os.File
	stderr *os.File
}

func swapConsoleStdio(t *testing.T) consoleStdio {
	t.Helper()
	dir := t.TempDir()
	stdinRead, stdinWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = stdinWrite.Close()
	stdout, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	origStdin, origStdout, origStderr := os.Stdin, os.Stdout, os.Stderr
	os.Stdin, os.Stdout, os.Stderr = stdinRead, stdout, stderr
	appLogger.SetOutput(stderr)
	t.Cleanup(func() {
		appLogger.SetOutput(origStderr)
		os.Stdin, os.Stdout, os.Stderr = origStdin, origStdout, origStderr
		_ = stdinRead.Close()
		_ = stdout.Close()
		_ = stderr.Close()
	})
	return consoleStdio{stdin: stdinRead, stdout: stdout, stderr: stderr}
}

func startOwnedFakeDaemon(t *testing.T) *daemonProcess {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "started")
	bin := writeFakeDaemon(t, []string{"apsigner starting"}, "ready", marker, "exec sleep 30")
	dp, err := startDaemonProcess(bin, t.TempDir())
	if err != nil {
		t.Fatalf("startDaemonProcess: %v", err)
	}
	t.Cleanup(dp.Stop)
	waitForFile(t, marker)
	return dp
}

func ownedDaemonModel(dp *daemonProcess) daemonModel {
	return newDaemonModel(daemonInfo{Status: daemonStatusStarting, Owned: true}, dp.events)
}

func assertConsoleCleanedUp(t *testing.T, stdio consoleStdio, dp *daemonProcess) {
	t.Helper()
	select {
	case <-dp.done:
	default:
		t.Fatal("owned apsigner still running after the console returned")
	}
	if os.Stdin != stdio.stdin || os.Stdout != stdio.stdout || os.Stderr != stdio.stderr {
		t.Fatal("stdio not restored after the console returned")
	}
}

// An external SIGINT ends the Bubble Tea program with ErrInterrupted. The
// console must still stop the apsigner it owns and restore stdio, and leave
// the exit to main.
func TestStartConsoleStopsOwnedDaemonOnInterrupt(t *testing.T) {
	stdio := swapConsoleStdio(t)
	dp := startOwnedFakeDaemon(t)

	// Keep SIGINT from killing the test binary until Bubble Tea's own
	// handler is in place.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT)
	defer signal.Stop(signals)

	codes := make(chan int, 1)
	go func() {
		codes <- startConsole(testConnector{}, t.TempDir(), "cosigner", nil, nil, false, dp, ownedDaemonModel(dp))
	}()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case code := <-codes:
			if code != 1 {
				t.Fatalf("exit code = %d, want 1", code)
			}
			assertConsoleCleanedUp(t, stdio, dp)
			stderr, err := os.ReadFile(stdio.stderr.Name())
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(stderr), "error running console: ") || !strings.Contains(string(stderr), "interrupted") {
				t.Fatalf("stderr does not report the interrupt:\n%s", stderr)
			}
			return
		case <-tick.C:
			_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
		case <-deadline:
			t.Fatal("console did not return after SIGINT")
		}
	}
}

type panickingConnector struct{}

func (panickingConnector) Connect() (io.ReadWriteCloser, error) {
	panic("connector exploded")
}

func (panickingConnector) Label() string {
	return "panicking"
}

// The signer pane connects in a Cmd goroutine. A panic there must end the
// program through the console's exit path: the owned apsigner stopped, stdio
// restored, exit code 2, and the stack trace written out.
func TestStartConsoleRecoversCmdPanic(t *testing.T) {
	stdio := swapConsoleStdio(t)
	dp := startOwnedFakeDaemon(t)
	dataDir := t.TempDir()

	codes := make(chan int, 1)
	go func() {
		codes <- startConsole(panickingConnector{}, dataDir, "cosigner", nil, nil, false, dp, ownedDaemonModel(dp))
	}()
	select {
	case code := <-codes:
		if code != 2 {
			t.Fatalf("exit code = %d, want 2", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("console did not return after a Cmd panic")
	}
	assertConsoleCleanedUp(t, stdio, dp)

	traces, err := filepath.Glob(filepath.Join(dataDir, "apconsole-panic-*.log"))
	if err != nil || len(traces) != 1 {
		t.Fatalf("panic traces = %v (%v), want one", traces, err)
	}
	trace, err := os.ReadFile(traces[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(trace), "connector exploded") || !strings.Contains(string(trace), "panickingConnector.Connect") {
		t.Fatalf("panic trace does not name the panic and where it happened:\n%s", trace)
	}
	stderr, err := os.ReadFile(stdio.stderr.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stderr), "stack trace written to "+traces[0]) {
		t.Fatalf("stderr does not point at the trace file:\n%s", stderr)
	}
}

type panicGuardTestModel struct {
	initCmd   tea.Cmd
	panicOn   string
	updateCmd tea.Cmd
}

type panicGuardTestMsg string

func (m panicGuardTestModel) Init() tea.Cmd {
	if m.panicOn == "init" {
		panic("init exploded")
	}
	return m.initCmd
}

func (m panicGuardTestModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if msg, ok := msg.(panicGuardTestMsg); ok && string(msg) == "update" {
		panic("update exploded")
	}
	return m, m.updateCmd
}

func (m panicGuardTestModel) View() string {
	if m.panicOn == "view" {
		panic("view exploded")
	}
	return ""
}

func panicGuardExplode() tea.Msg {
	panic("cmd exploded")
}

func panicGuardSendUpdate() tea.Msg {
	return panicGuardTestMsg("update")
}

func TestPanicGuardRecordsEveryModelPath(t *testing.T) {
	swapConsoleStdio(t)
	idle := func() tea.Msg { time.Sleep(10 * time.Millisecond); return nil }
	tests := []struct {
		name  string
		model panicGuardTestModel
		want  string
	}{
		{name: "init", model: panicGuardTestModel{panicOn: "init"}, want: "init exploded"},
		{name: "view", model: panicGuardTestModel{panicOn: "view"}, want: "view exploded"},
		{name: "update", model: panicGuardTestModel{initCmd: panicGuardSendUpdate}, want: "update exploded"},
		{name: "cmd", model: panicGuardTestModel{initCmd: panicGuardExplode}, want: "cmd exploded"},
		{name: "batch command", model: panicGuardTestModel{initCmd: tea.Batch(idle, panicGuardExplode)}, want: "cmd exploded"},
		{
			name:  "command from update",
			model: panicGuardTestModel{initCmd: func() tea.Msg { return panicGuardTestMsg("tick") }, updateCmd: panicGuardExplode},
			want:  "cmd exploded",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guard, guarded := newPanicGuard(tt.model)
			p := tea.NewProgram(guarded, tea.WithInput(nil), tea.WithOutput(io.Discard), tea.WithoutSignalHandler())
			done := make(chan error, 1)
			go func() {
				_, err := p.Run()
				done <- err
			}()
			select {
			case err := <-done:
				// A model method's panic reaches Bubble Tea's recover; a
				// command's panic quits the program.
				if err != nil && !errors.Is(err, tea.ErrProgramPanic) {
					t.Fatalf("Run error = %v, want nil or ErrProgramPanic", err)
				}
			case <-time.After(5 * time.Second):
				p.Kill()
				t.Fatal("program did not end after the panic")
			}
			caught := guard.recorded()
			if caught == nil {
				t.Fatal("no panic recorded")
			}
			if caught.value != tt.want {
				t.Fatalf("recorded panic = %v, want %q", caught.value, tt.want)
			}
			if !strings.Contains(string(caught.stack), "panicGuardTestModel") && !strings.Contains(string(caught.stack), "panicGuardExplode") {
				t.Fatalf("recorded stack does not show where the panic happened:\n%s", caught.stack)
			}
			if _, ok := guard.finalModel(nil).(panicGuardTestModel); !ok {
				t.Fatalf("final model = %T, want the last model", guard.finalModel(nil))
			}
		})
	}
}
