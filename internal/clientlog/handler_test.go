// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientlog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

// recordingSink keeps every record it is given.
type recordingSink struct {
	mu      sync.Mutex
	records []Record
}

func (s *recordingSink) WriteRecord(record Record) error {
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

// testLogger returns a logger on a private pipeline at the given level.
func testLogger(level slog.Level) (*slog.Logger, *recordingSink, *pipeline) {
	sink := &recordingSink{}
	p := &pipeline{sink: sink}
	p.level.Set(level)
	return slog.New(&handler{pipeline: p}), sink, p
}

func TestHandlerRendersRecords(t *testing.T) {
	boom := errors.New("connection reset")
	for _, tc := range []struct {
		name string
		log  func(*slog.Logger)
		want string
	}{
		{"component", func(l *slog.Logger) { l.Info("loaded", "component", "cache") }, "[cache] loaded"},
		{"no component", func(l *slog.Logger) { l.Info("loaded") }, "[aplane] loaded"},
		{"warning label", func(l *slog.Logger) { l.Warn("tampered", "component", "cache") }, "[cache] warning: tampered"},
		{"error label", func(l *slog.Logger) { l.Error("panic", "component", "ssh") }, "[ssh] error: panic"},
		{"debug has no label", func(l *slog.Logger) { l.Debug("hit", "component", "cache") }, "[cache] hit"},
		{"attributes", func(l *slog.Logger) {
			l.Warn("admin notification dropped", "type", "sign_request", "id", "x1", "dropped_total", 3)
		}, "[aplane] warning: admin notification dropped type=sign_request id=x1 dropped_total=3"},
		{"error attribute", func(l *slog.Logger) {
			l.Debug("failed to close response body", "component", "signerclient", "error", boom)
		}, `[signerclient] failed to close response body error="connection reset"`},
		{"quoting", func(l *slog.Logger) { l.Info("m", "a", "", "b", `x"y`, "c", "d=e") }, `[aplane] m a="" b="x\"y" c="d=e"`},
		{"inherited attributes", func(l *slog.Logger) {
			l.With("component", "cache").With("network", "testnet").Info("m", "n", 1)
		}, "[cache] m network=testnet n=1"},
		{"with group", func(l *slog.Logger) {
			l.WithGroup("rpc").WithGroup("out").Info("m", "id", 7)
		}, "[aplane] m rpc.out.id=7"},
		{"inherited before group", func(l *slog.Logger) {
			l.With("component", "cache").WithGroup("rpc").Info("m", "id", 7)
		}, "[cache] m rpc.id=7"},
		{"group attribute", func(l *slog.Logger) { l.Info("m", slog.Group("g", "a", 1, "b", 2)) }, "[aplane] m g.a=1 g.b=2"},
		{"inline group", func(l *slog.Logger) { l.Info("m", slog.Group("", "a", 1)) }, "[aplane] m a=1"},
		{"empty group vanishes", func(l *slog.Logger) { l.Info("m", slog.Group("g")) }, "[aplane] m"},
		{"zero attribute vanishes", func(l *slog.Logger) { l.Info("m", slog.Attr{}) }, "[aplane] m"},
		{"grouped component is ordinary", func(l *slog.Logger) {
			l.WithGroup("g").Info("m", "component", "cache")
		}, "[aplane] m g.component=cache"},
		{"plugin stderr", func(l *slog.Logger) {
			l.Info("cannot find module foo", "component", "plugin", "plugin", "mithras", "stream", "stderr")
		}, "[plugin mithras stderr] cannot find module foo"},
		{"plugin replay keeps the prefix", func(l *slog.Logger) {
			l.Warn("cannot find module foo", "component", "plugin", "plugin", "mithras", "stream", "stderr")
		}, "[plugin mithras stderr] warning: cannot find module foo"},
		{"plugin banner", func(l *slog.Logger) {
			l.Info("Running in sandbox", "component", "plugin", "plugin", "mithras")
		}, "[plugin mithras] Running in sandbox"},
		{"plugin named after a host component", func(l *slog.Logger) {
			l.Warn("SECURITY: tampered", "component", "plugin", "plugin", "cache", "stream", "stderr")
		}, "[plugin cache stderr] warning: SECURITY: tampered"},
		{"plugin attributes survive elsewhere", func(l *slog.Logger) {
			l.Info("m", "component", "cache", "plugin", "x", "stream", "y")
		}, "[cache] m plugin=x stream=y"},
		{"grouped plugin field kept", func(l *slog.Logger) {
			l.With("component", "plugin", "plugin", "x").WithGroup("g").Info("m", "plugin", "y")
		}, "[plugin x] m g.plugin=y"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, sink, _ := testLogger(slog.LevelDebug)
			tc.log(logger)
			if got := sink.lines(); !slices.Equal(got, []string{tc.want}) {
				t.Fatalf("lines = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHandlerWithAttrsDoesNotShareState(t *testing.T) {
	logger, sink, _ := testLogger(slog.LevelInfo)
	base := logger.With("a", 1)

	base.With("b", 2).Info("first")
	base.With("c", 3).Info("second")
	base.Info("third")

	want := []string{"[aplane] first a=1 b=2", "[aplane] second a=1 c=3", "[aplane] third a=1"}
	if got := sink.lines(); !slices.Equal(got, want) {
		t.Fatalf("lines = %q, want %q", got, want)
	}
}

func TestHandlerFiltersByCurrentLevel(t *testing.T) {
	logger, sink, p := testLogger(slog.LevelWarn)

	logger.Info("hidden")
	logger.Warn("shown")
	p.level.Set(slog.LevelInfo)
	logger.Info("now shown")
	p.level.Set(slog.LevelError)
	logger.Warn("filtered warning")

	want := []string{"[aplane] warning: shown", "[aplane] now shown"}
	if got := sink.lines(); !slices.Equal(got, want) {
		t.Fatalf("lines = %q, want %q", got, want)
	}
}

func TestHandlerEscapesTheWholeLine(t *testing.T) {
	logger, sink, _ := testLogger(slog.LevelInfo)

	logger.Info("msg\x1b[2J\nnext",
		"component", "plugin", "plugin", "evil\x1b]0;x\x07", "stream", "std\x1berr",
		"attr", "value\x1b[1m", "err", errors.New("bad\u202eerror"))

	lines := sink.lines()
	if len(lines) != 1 {
		t.Fatalf("lines = %q, want one", lines)
	}
	if strings.ContainsAny(lines[0], "\x1b\x07\u202e\n") {
		t.Fatalf("a control character survived: %q", lines[0])
	}
	if !strings.HasPrefix(lines[0], "[plugin ") {
		t.Fatalf("line %q lost the trusted prefix", lines[0])
	}
}

func TestLinesAreBoundedAfterEscaping(t *testing.T) {
	for _, tc := range []struct {
		name string
		log  func(*slog.Logger)
	}{
		{"long message", func(l *slog.Logger) { l.Info(strings.Repeat("x", 3*maxLineBytes)) }},
		{"escaping expands it", func(l *slog.Logger) { l.Info(strings.Repeat("\x1b", maxLineBytes)) }},
		{"long attribute", func(l *slog.Logger) { l.Info("m", "a", strings.Repeat("y", 3*maxLineBytes)) }},
		{"long plugin name", func(l *slog.Logger) {
			l.Info("m", "component", "plugin", "plugin", strings.Repeat("\x07", maxLineBytes))
		}},
		{"multi-byte text at the cut", func(l *slog.Logger) { l.Info(strings.Repeat("日本語", maxLineBytes)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, sink, _ := testLogger(slog.LevelInfo)
			tc.log(logger)
			line := sink.lines()[0]
			if len(line) > maxLineBytes {
				t.Fatalf("line is %d bytes, over the %d limit", len(line), maxLineBytes)
			}
			if !strings.HasSuffix(line, truncationMarker) {
				t.Fatalf("line doesn't end with the truncation marker: %.40q", line[len(line)-40:])
			}
			if !utf8.ValidString(line) {
				t.Fatal("truncation produced invalid UTF-8")
			}
		})
	}
}

func TestShortLineIsNotMarked(t *testing.T) {
	logger, sink, _ := testLogger(slog.LevelInfo)
	logger.Info(strings.Repeat("x", 100))
	if line := sink.lines()[0]; strings.Contains(line, truncationMarker) {
		t.Fatalf("line %q was marked truncated", line)
	}
}

func TestWriterSinkKeepsLinesWhole(t *testing.T) {
	var out syncBuffer
	p := &pipeline{sink: WriterSink(&out)}
	p.level.Set(slog.LevelInfo)
	logger := slog.New(&handler{pipeline: p})

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 50 {
				logger.Info(fmt.Sprintf("g%d-%d", g, i))
			}
		}()
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 400 {
		t.Fatalf("got %d lines, want 400", len(lines))
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "[aplane] g") {
			t.Fatalf("interleaved line: %q", line)
		}
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// blockingSink holds its first write open until released.
type blockingSink struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	wrote   chan struct{}
}

func (s *blockingSink) WriteRecord(Record) error {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	close(s.wrote)
	return nil
}

func TestSetSinkWaitsForAWriteToTheOldSink(t *testing.T) {
	old := &blockingSink{entered: make(chan struct{}), release: make(chan struct{}), wrote: make(chan struct{})}
	p := &pipeline{sink: old}
	p.level.Set(slog.LevelInfo)
	logger := slog.New(&handler{pipeline: p})

	go logger.Info("in flight")
	<-old.entered

	swapped := make(chan struct{})
	go func() {
		p.setSink(&recordingSink{})
		close(swapped)
	}()
	select {
	case <-swapped:
		t.Fatal("the sink changed while a write to the old one was in progress")
	case <-shortWait():
	}

	close(old.release)
	<-swapped
	select {
	case <-old.wrote:
	default:
		t.Fatal("the swap finished before the old write did")
	}
}

func TestParseLevel(t *testing.T) {
	for _, name := range LevelNames {
		level, err := ParseLevel(name)
		if err != nil {
			t.Fatalf("ParseLevel(%q) error = %v", name, err)
		}
		if got := LevelName(level); got != name {
			t.Fatalf("LevelName(ParseLevel(%q)) = %q", name, got)
		}
	}
	for _, name := range []string{"", "notice", "INFO", "warning"} {
		if _, err := ParseLevel(name); err == nil {
			t.Fatalf("ParseLevel(%q) accepted", name)
		}
	}
}

func TestStartLevel(t *testing.T) {
	t.Setenv("APSHELL_DEBUG", "")
	if got := StartLevel(slog.LevelWarn); got != slog.LevelWarn {
		t.Fatalf("StartLevel() = %v, want the host default", got)
	}
	if got := StartLevel(slog.LevelInfo); got != slog.LevelInfo {
		t.Fatalf("StartLevel() = %v, want the host default", got)
	}
	t.Setenv("APSHELL_DEBUG", "0") // Any value counts, as it always has.
	if got := StartLevel(slog.LevelWarn); got != slog.LevelDebug {
		t.Fatalf("StartLevel() = %v, want debug", got)
	}
}

func restoreDefaults(t *testing.T) {
	t.Helper()
	previous := slog.Default()
	flags := log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(previous)
		log.SetOutput(os.Stderr)
		log.SetFlags(flags)
		slog.SetLogLoggerLevel(slog.LevelInfo)
		process = pipeline{}
	})
}

func TestInstallRoutesTheDefaultLoggerAndStandardLog(t *testing.T) {
	restoreDefaults(t)
	sink := &recordingSink{}
	Install(slog.LevelWarn, sink)

	slog.Info("routine")
	slog.Warn("attention")
	log.Print("unclassified text")
	SetLevel(slog.LevelError)
	slog.Warn("filtered")

	want := []string{"[aplane] warning: attention", "[aplane] warning: unclassified text"}
	if got := sink.lines(); !slices.Equal(got, want) {
		t.Fatalf("lines = %q, want %q", got, want)
	}
	if Level() != slog.LevelError {
		t.Fatalf("Level() = %v, want error", Level())
	}
}

func TestSourceLoggerMadeAtCallTimeFollowsInstall(t *testing.T) {
	restoreDefaults(t)
	componentLogger := func() *slog.Logger { return slog.With("component", "cache") }

	first := &recordingSink{}
	Install(slog.LevelInfo, first)
	componentLogger().Info("one")

	second := &recordingSink{}
	SetSink(second)
	componentLogger().Info("two")

	if got := first.lines(); !slices.Equal(got, []string{"[cache] one"}) {
		t.Fatalf("first sink = %q", got)
	}
	if got := second.lines(); !slices.Equal(got, []string{"[cache] two"}) {
		t.Fatalf("second sink = %q", got)
	}
}

func TestHandlerIgnoresContextCancellation(t *testing.T) {
	logger, sink, _ := testLogger(slog.LevelInfo)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	logger.InfoContext(ctx, "still logged")
	if len(sink.lines()) != 1 {
		t.Fatal("a cancelled context lost the record")
	}
}
