// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package clientlog is the diagnostic pipeline of APlane's client programs.
//
// Packages that have something to report call log/slog and know nothing about
// this package. Each host program calls Install once, before it builds anything
// that can log, and so decides where diagnostics go and which ones are shown.
// That lets a shared package log without knowing whether it runs under a terminal,
// a full-screen interface, or an MCP host whose stdout carries the protocol.
//
// Logs are only one kind of client output. Command results, prompts, and progress
// have their own paths; see "Client Output and Logging" in docs/ARCH_SHELL.md.
package clientlog

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
)

// Record is one rendered diagnostic, ready to display. Line is escaped and
// bounded and has no trailing newline. Level is kept so a bounded queue can
// choose what to evict.
type Record struct {
	Level slog.Level
	Line  string
}

// Sink receives records one at a time. A sink must not log.
type Sink interface {
	WriteRecord(Record) error
}

// pipeline is what the handler writes through. The same lock covers every write
// and every sink change, so a change returns only after writes to the old sink
// have finished.
type pipeline struct {
	level slog.LevelVar
	mu    sync.Mutex
	sink  Sink
}

func (p *pipeline) write(record Record) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sink == nil {
		return nil
	}
	return p.sink.WriteRecord(record)
}

func (p *pipeline) setSink(sink Sink) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sink = sink
}

var process pipeline

// Install makes this package the process's logging pipeline, at the given level
// and writing to sink. Text that reaches the standard log package has no level
// of its own, so it is treated as a warning rather than being hidden by default.
func Install(level slog.Level, sink Sink) {
	process.level.Set(level)
	process.setSink(sink)
	slog.SetDefault(slog.New(&handler{pipeline: &process}))
	slog.SetLogLoggerLevel(slog.LevelWarn)
}

// SetSink replaces the installed sink. It returns after any write to the old
// sink has finished, so the caller may then close what the old sink wrote to.
func SetSink(sink Sink) {
	process.setSink(sink)
}

// Level returns the process's current level.
func Level() slog.Level {
	return process.level.Level()
}

// SetLevel changes the process's level. It is safe to call at any time.
func SetLevel(level slog.Level) {
	process.level.Set(level)
}

// StartLevel returns the level a host should install. APSHELL_DEBUG, if set to
// anything, selects debug over the host's own default.
func StartLevel(hostDefault slog.Level) slog.Level {
	if os.Getenv("APSHELL_DEBUG") != "" {
		return slog.LevelDebug
	}
	return hostDefault
}

// LevelNames lists the accepted level names, least to most verbose.
var LevelNames = []string{"error", "warn", "info", "debug"}

// ParseLevel returns the level with the given name.
func ParseLevel(name string) (slog.Level, error) {
	switch name {
	case "error":
		return slog.LevelError, nil
	case "warn":
		return slog.LevelWarn, nil
	case "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	}
	return 0, fmt.Errorf("unknown log level %q", name)
}

// LevelName returns the name of level, or the nearest name below it.
func LevelName(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return "error"
	case level >= slog.LevelWarn:
		return "warn"
	case level >= slog.LevelInfo:
		return "info"
	}
	return "debug"
}

// WriterSink writes each record to w as one line in a single Write.
func WriterSink(w io.Writer) Sink {
	return writerSink{w: w}
}

type writerSink struct {
	w io.Writer
}

func (s writerSink) WriteRecord(record Record) error {
	return writeLine(s.w, record.Line)
}

func writeLine(w io.Writer, line string) error {
	data := line + "\n"
	n, err := io.WriteString(w, data)
	if err == nil && n < len(data) {
		return io.ErrShortWrite
	}
	return err
}
