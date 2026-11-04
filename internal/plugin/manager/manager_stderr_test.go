// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package manager

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/plugin/manifest"
)

// recordingWriter keeps each Write separately, to check the one-line-per-Write
// contract that TUI hosts rely on.
type recordingWriter struct {
	mu     sync.Mutex
	writes []string
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes = append(w.writes, string(p))
	return len(p), nil
}

func (w *recordingWriter) lines() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.writes...)
}

// runStderrMonitor feeds chunks to a monitor exactly as written and waits for it
// to reach EOF.
func runStderrMonitor(t *testing.T, m *Manager, instance *Instance, chunks ...string) {
	t.Helper()
	reader, writer := io.Pipe()
	instance.stderr = reader
	instance.stderrDone = make(chan struct{})
	go m.monitorStderr(instance)
	for _, chunk := range chunks {
		if _, err := writer.Write([]byte(chunk)); err != nil {
			t.Fatalf("write stderr: %v", err)
		}
	}
	_ = writer.Close()
	select {
	case <-instance.stderrDone:
	case <-time.After(5 * time.Second):
		t.Fatal("stderr monitor did not finish; a stalled monitor blocks the plugin")
	}
}

func stderrTestInstance() *Instance {
	return &Instance{
		Plugin: &discovery.Plugin{Manifest: &manifest.Manifest{Name: "mithras"}},
	}
}

func stderrTestManager(gate func() bool) (*Manager, *recordingWriter) {
	m := NewManager()
	out := &recordingWriter{}
	m.SetStderrWriter(out)
	m.SetStderrGate(gate)
	return m, out
}

func assertWrites(t *testing.T, got, want []string) {
	t.Helper()
	if strings.Join(got, "") != strings.Join(want, "") || len(got) != len(want) {
		t.Fatalf("writes = %q, want %q", got, want)
	}
}

func TestStderrShownOneLinePerWriteWithoutGate(t *testing.T) {
	m, out := stderrTestManager(nil)

	runStderrMonitor(t, m, stderrTestInstance(), "first li", "ne\nsecond\nthird", " line\r\nno newline")

	assertWrites(t, out.lines(), []string{
		"[mithras stderr]: first line\n",
		"[mithras stderr]: second\n",
		"[mithras stderr]: third line\n",
		"[mithras stderr]: no newline\n",
	})
}

func TestStderrHiddenByGateUntilReportedOnFailure(t *testing.T) {
	m, out := stderrTestManager(func() bool { return false })
	instance := stderrTestInstance()

	runStderrMonitor(t, m, instance, "noise\n", "crash reason\n")
	if got := out.lines(); len(got) != 0 {
		t.Fatalf("hidden stderr reached the writer: %q", got)
	}

	m.reportHeldStderr(instance)
	want := []string{"[mithras stderr]: noise\n", "[mithras stderr]: crash reason\n"}
	assertWrites(t, out.lines(), want)

	m.reportHeldStderr(instance)
	assertWrites(t, out.lines(), want)
}

func TestStderrGateFollowsChangesWhileRunning(t *testing.T) {
	var visible atomic.Bool
	m, out := stderrTestManager(visible.Load)
	instance := stderrTestInstance()
	reader, writer := io.Pipe()
	instance.stderr = reader
	instance.stderrDone = make(chan struct{})
	go m.monitorStderr(instance)

	write := func(s string) {
		t.Helper()
		if _, err := writer.Write([]byte(s)); err != nil {
			t.Fatalf("write stderr: %v", err)
		}
	}
	write("hidden\n")
	write("sync\n") // The read of this line proves the monitor finished the first.
	visible.Store(true)
	write("shown\n")
	_ = writer.Close()
	<-instance.stderrDone

	for _, line := range out.lines() {
		if strings.Contains(line, "hidden") {
			t.Fatalf("line written while hidden reached the writer: %q", out.lines())
		}
	}
	if got := out.lines(); len(got) == 0 || got[len(got)-1] != "[mithras stderr]: shown\n" {
		t.Fatalf("writes = %q, want the line written while visible", got)
	}
}

func TestStderrEscapesTerminalControls(t *testing.T) {
	m, out := stderrTestManager(nil)

	runStderrMonitor(t, m, stderrTestInstance(), "ok\x1b[2J\rfake prompt\n")

	assertWrites(t, out.lines(), []string{`[mithras stderr]: ok\x1b[2J\rfake prompt` + "\n"})
}

func hostilePlugin(name string) *discovery.Plugin {
	return &discovery.Plugin{Manifest: &manifest.Manifest{Name: name}}
}

func TestPluginLinesEscapeHostileManifestName(t *testing.T) {
	const name = "x\x1b[2J\u202e\ny"
	const escaped = `x\x1b[2J\u202e\ny`

	assertSafe := func(t *testing.T, lines []string) {
		t.Helper()
		if len(lines) == 0 {
			t.Fatal("expected output")
		}
		for _, line := range lines {
			body := strings.TrimSuffix(line, "\n")
			if strings.ContainsAny(body, "\x1b\u202e\n\r") {
				t.Fatalf("control character reached the writer: %q", line)
			}
			if !strings.Contains(body, escaped) {
				t.Fatalf("line %q does not show the escaped name %q", line, escaped)
			}
			if !strings.HasSuffix(line, "\n") {
				t.Fatalf("line %q lost its trusted newline", line)
			}
		}
	}

	t.Run("visible stderr", func(t *testing.T) {
		m, out := stderrTestManager(nil)
		runStderrMonitor(t, m, &Instance{Plugin: hostilePlugin(name)}, "hello\n")
		assertSafe(t, out.lines())
	})

	t.Run("held stderr replayed on failure", func(t *testing.T) {
		m, out := stderrTestManager(func() bool { return false })
		instance := &Instance{Plugin: hostilePlugin(name)}
		runStderrMonitor(t, m, instance, "hello\n")
		m.reportHeldStderr(instance)
		assertSafe(t, out.lines())
	})

	t.Run("sandbox banner", func(t *testing.T) {
		m, out := stderrTestManager(nil)
		m.emitSandboxBanner(hostilePlugin(name))
		assertSafe(t, out.lines())
	})
}

func TestSandboxBannerFollowsGate(t *testing.T) {
	m, out := stderrTestManager(func() bool { return false })

	m.emitSandboxBanner(hostilePlugin("mithras"))

	if got := out.lines(); len(got) != 0 {
		t.Fatalf("hidden banner reached the writer: %q", got)
	}
}

func TestStderrOverlongLineKeepsDraining(t *testing.T) {
	m, out := stderrTestManager(nil)
	long := strings.Repeat("x", 3*maxStderrLineBytes)

	runStderrMonitor(t, m, stderrTestInstance(), long+"\n", "after\n")

	lines := out.lines()
	if len(lines) < 4 {
		t.Fatalf("got %d writes, want the long line in pieces", len(lines))
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "[mithras stderr]: ") || !strings.HasSuffix(line, "\n") {
			t.Fatalf("malformed write: %.60q", line)
		}
	}
	if got := strings.Count(strings.Join(lines, ""), "x"); got != len(long) {
		t.Fatalf("kept %d of %d bytes", got, len(long))
	}
	if last := lines[len(lines)-1]; last != "[mithras stderr]: after\n" {
		t.Fatalf("last write = %q", last)
	}
}

func TestHeldStderrKeepsNewestLines(t *testing.T) {
	m, out := stderrTestManager(func() bool { return false })
	instance := stderrTestInstance()

	total := maxHeldStderrLines + 5
	chunks := make([]string, total)
	for i := range chunks {
		chunks[i] = fmt.Sprintf("line %d\n", i)
	}
	runStderrMonitor(t, m, instance, chunks...)
	m.reportHeldStderr(instance)

	lines := out.lines()
	if len(lines) != maxHeldStderrLines {
		t.Fatalf("reported %d lines, want %d", len(lines), maxHeldStderrLines)
	}
	if want := "[mithras stderr]: line 5\n"; lines[0] != want {
		t.Fatalf("oldest kept = %q, want %q", lines[0], want)
	}
	if want := fmt.Sprintf("[mithras stderr]: line %d\n", total-1); lines[len(lines)-1] != want {
		t.Fatalf("newest kept = %q, want %q", lines[len(lines)-1], want)
	}
}

// startCrashingPlugin runs a real process that logs its reason and exits, with
// no JSON-RPC peer, so a host call on it fails the way a crashed plugin does.
func startCrashingPlugin(t *testing.T, m *Manager) *Instance {
	t.Helper()
	cmd := exec.Command("sh", "-c", "echo 'cannot find module foo' >&2; exit 1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe() error = %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe() error = %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("StderrPipe() error = %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start() error = %v", err)
	}
	reader, writer := io.Pipe()
	_ = writer.Close()
	client := jsonrpc.NewClient(reader, &bytes.Buffer{})
	client.Start()

	instance := &Instance{
		Plugin: &discovery.Plugin{
			Manifest: &manifest.Manifest{Name: "mithras", Timeout: 1},
		},
		Process:    cmd,
		Client:     client,
		stdin:      stdin,
		stdout:     stdout,
		stderr:     stderr,
		stderrDone: make(chan struct{}),
	}
	go m.monitorStderr(instance)
	return instance
}

func TestFailedPluginReportsHiddenStderr(t *testing.T) {
	tests := []struct {
		name    string
		failure string
		setup   func(*Manager)
		run     func(*Manager) error
	}{
		{
			name: "during initialize",
			setup: func(m *Manager) {
				m.initializePluginHook = func(*Instance, runtimeConfig) error {
					return io.ErrUnexpectedEOF
				}
			},
			run: func(m *Manager) error {
				_, err := m.StartPlugin("mithras")
				return err
			},
		},
		{
			name: "during execute",
			setup: func(m *Manager) {
				m.initializePluginHook = func(*Instance, runtimeConfig) error { return nil }
			},
			run: func(m *Manager) error {
				_, err := m.ExecuteCommand("mithras", "echo", nil, jsonrpc.Context{})
				return err
			},
		},
		{
			name: "during signTransactions",
			setup: func(m *Manager) {
				m.initializePluginHook = func(*Instance, runtimeConfig) error { return nil }
			},
			run: func(m *Manager) error {
				_, err := m.SignTransactions("mithras", jsonrpc.SignTransactionsParams{})
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, out := stderrTestManager(func() bool { return false })
			m.cachedPlugins = []*discovery.Plugin{{
				Manifest: &manifest.Manifest{
					Name:     "mithras",
					Commands: []manifest.Command{{Name: "echo", Description: "echo"}},
				},
			}}
			m.startPluginInstanceHook = func(*discovery.Plugin, runtimeConfig) (*Instance, error) {
				return startCrashingPlugin(t, m), nil
			}
			tt.setup(m)

			if err := tt.run(m); err == nil {
				t.Fatal("expected the host call to fail")
			}
			assertWrites(t, out.lines(), []string{"[mithras stderr]: cannot find module foo\n"})
		})
	}
}
