// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package manager

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/clientlog"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/plugin/manifest"
)

// recordingSink keeps what reaches the end of the logging pipeline.
type recordingSink struct {
	mu      sync.Mutex
	records []clientlog.Record
}

func (s *recordingSink) WriteRecord(record clientlog.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, record)
	return nil
}

func (s *recordingSink) lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	lines := make([]string, len(s.records))
	for i, record := range s.records {
		lines[i] = record.Line
	}
	return lines
}

// installLogs runs the real pipeline for one test, so these tests see what a host
// shows: the prefix, the escaping, and the level filter.
func installLogs(t *testing.T, level slog.Level) *recordingSink {
	t.Helper()
	previous := slog.Default()
	flags := log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(previous)
		log.SetOutput(os.Stderr)
		log.SetFlags(flags)
	})
	sink := &recordingSink{}
	clientlog.Install(level, sink)
	return sink
}

// runStderrMonitor feeds chunks to a monitor exactly as written and waits for it
// to reach EOF.
func runStderrMonitor(t *testing.T, instance *Instance, chunks ...string) {
	t.Helper()
	reader, writer := io.Pipe()
	instance.stderr = reader
	instance.stderrDone = make(chan struct{})
	go instance.monitorStderr()
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
	return &Instance{Plugin: testPlugin("mithras")}
}

func testPlugin(name string) *discovery.Plugin {
	return &discovery.Plugin{Manifest: &manifest.Manifest{Name: name}}
}

func assertLines(t *testing.T, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("lines = %q, want %q", got, want)
	}
}

func TestStderrShownOneLineAtATimeAtInfo(t *testing.T) {
	sink := installLogs(t, slog.LevelInfo)

	runStderrMonitor(t, stderrTestInstance(), "first li", "ne\nsecond\nthird", " line\r\nno newline")

	assertLines(t, sink.lines(), []string{
		"[plugin mithras stderr] first line",
		"[plugin mithras stderr] second",
		"[plugin mithras stderr] third line",
		"[plugin mithras stderr] no newline",
	})
}

func TestStderrIsLoggedAtInfoWhateverItSays(t *testing.T) {
	sink := installLogs(t, slog.LevelInfo)

	runStderrMonitor(t, stderrTestInstance(), "ERROR: FATAL\nlevel=error msg=boom\n")

	for _, record := range sink.records {
		if record.Level != slog.LevelInfo {
			t.Fatalf("record %q has level %v; a plugin's text must not set it", record.Line, record.Level)
		}
	}
}

func TestStderrHiddenByDefaultUntilReportedOnFailure(t *testing.T) {
	sink := installLogs(t, slog.LevelWarn)
	instance := stderrTestInstance()

	runStderrMonitor(t, instance, "noise\n", "crash reason\n")
	if got := sink.lines(); len(got) != 0 {
		t.Fatalf("hidden stderr reached the sink: %q", got)
	}

	instance.reportHeldStderr()
	want := []string{
		"[plugin mithras stderr] warning: noise",
		"[plugin mithras stderr] warning: crash reason",
	}
	assertLines(t, sink.lines(), want)

	instance.reportHeldStderr()
	assertLines(t, sink.lines(), want)
}

func TestStderrFollowsTheLevelWhileRunning(t *testing.T) {
	sink := installLogs(t, slog.LevelWarn)
	instance := stderrTestInstance()
	reader, writer := io.Pipe()
	instance.stderr = reader
	instance.stderrDone = make(chan struct{})
	go instance.monitorStderr()

	write := func(s string) {
		t.Helper()
		if _, err := writer.Write([]byte(s)); err != nil {
			t.Fatalf("write stderr: %v", err)
		}
	}
	write("hidden\n")
	write("sync\n") // Reading this line proves the monitor finished the first.
	clientlog.SetLevel(slog.LevelInfo)
	write("shown\n")
	_ = writer.Close()
	<-instance.stderrDone

	lines := sink.lines()
	if len(lines) == 0 || lines[len(lines)-1] != "[plugin mithras stderr] shown" {
		t.Fatalf("lines = %q, want the line written after the level changed", lines)
	}
	if slices.Contains(lines, "[plugin mithras stderr] hidden") {
		t.Fatalf("lines = %q, a hidden line was shown", lines)
	}
}

func TestStderrEscapesTerminalControls(t *testing.T) {
	sink := installLogs(t, slog.LevelInfo)

	runStderrMonitor(t, stderrTestInstance(), "ok\x1b[2J\rfake prompt\n")

	assertLines(t, sink.lines(), []string{`[plugin mithras stderr] ok\x1b[2J\rfake prompt`})
}

func TestPluginCannotPassAsAHostComponent(t *testing.T) {
	sink := installLogs(t, slog.LevelInfo)

	runStderrMonitor(t, &Instance{Plugin: testPlugin("cache")}, "SECURITY: all is well\n")

	assertLines(t, sink.lines(), []string{"[plugin cache stderr] SECURITY: all is well"})
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
			if strings.ContainsAny(line, "\x1b\u202e\n\r") {
				t.Fatalf("control character reached the sink: %q", line)
			}
			if !strings.HasPrefix(line, "[plugin "+escaped) {
				t.Fatalf("line %q does not lead with the escaped name %q", line, escaped)
			}
		}
	}

	t.Run("logged stderr", func(t *testing.T) {
		sink := installLogs(t, slog.LevelInfo)
		runStderrMonitor(t, &Instance{Plugin: testPlugin(name)}, "hello\n")
		assertSafe(t, sink.lines())
	})

	t.Run("held stderr replayed on failure", func(t *testing.T) {
		sink := installLogs(t, slog.LevelWarn)
		instance := &Instance{Plugin: testPlugin(name)}
		runStderrMonitor(t, instance, "hello\n")
		instance.reportHeldStderr()
		assertSafe(t, sink.lines())
	})

	t.Run("sandbox banner", func(t *testing.T) {
		sink := installLogs(t, slog.LevelInfo)
		logSandboxBanner(testPlugin(name))
		assertSafe(t, sink.lines())
	})
}

func TestSandboxBannerIsRoutineDetail(t *testing.T) {
	sink := installLogs(t, slog.LevelWarn)

	logSandboxBanner(testPlugin("mithras"))

	if got := sink.lines(); len(got) != 0 {
		t.Fatalf("banner shown at the default level: %q", got)
	}
}

func TestStderrOverlongLineKeepsDraining(t *testing.T) {
	sink := installLogs(t, slog.LevelInfo)
	long := strings.Repeat("x", 3*maxStderrLineBytes)

	runStderrMonitor(t, stderrTestInstance(), long+"\n", "after\n")

	lines := sink.lines()
	if len(lines) < 4 {
		t.Fatalf("got %d lines, want the long line in pieces", len(lines))
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "[plugin mithras stderr] ") {
			t.Fatalf("malformed line: %.60q", line)
		}
	}
	if got := strings.Count(strings.Join(lines, ""), "x"); got != len(long) {
		t.Fatalf("kept %d of %d bytes; a piece must fit in one log line", got, len(long))
	}
	if last := lines[len(lines)-1]; last != "[plugin mithras stderr] after" {
		t.Fatalf("last line = %q", last)
	}
}

func TestHeldStderrKeepsNewestLines(t *testing.T) {
	sink := installLogs(t, slog.LevelWarn)
	instance := stderrTestInstance()

	total := maxHeldStderrLines + 5
	chunks := make([]string, total)
	for i := range chunks {
		chunks[i] = fmt.Sprintf("line %d\n", i)
	}
	runStderrMonitor(t, instance, chunks...)
	instance.reportHeldStderr()

	lines := sink.lines()
	if len(lines) != maxHeldStderrLines {
		t.Fatalf("reported %d lines, want %d", len(lines), maxHeldStderrLines)
	}
	if want := "[plugin mithras stderr] warning: line 5"; lines[0] != want {
		t.Fatalf("oldest kept = %q, want %q", lines[0], want)
	}
	if want := fmt.Sprintf("[plugin mithras stderr] warning: line %d", total-1); lines[len(lines)-1] != want {
		t.Fatalf("newest kept = %q, want %q", lines[len(lines)-1], want)
	}
}

// startCrashingPlugin runs a real process that logs its reason and exits, with
// no JSON-RPC peer, so a host call on it fails the way a crashed plugin does.
func startCrashingPlugin(t *testing.T) *Instance {
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
	go instance.monitorStderr()
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
			sink := installLogs(t, slog.LevelWarn)
			m := NewManager()
			m.cachedPlugins = []*discovery.Plugin{{
				Manifest: &manifest.Manifest{
					Name:     "mithras",
					Commands: []manifest.Command{{Name: "echo", Description: "echo"}},
				},
			}}
			m.startPluginInstanceHook = func(*discovery.Plugin, runtimeConfig) (*Instance, error) {
				return startCrashingPlugin(t), nil
			}
			tt.setup(m)

			if err := tt.run(m); err == nil {
				t.Fatal("expected the host call to fail")
			}
			assertLines(t, sink.lines(), []string{"[plugin mithras stderr] warning: cannot find module foo"})
		})
	}
}
