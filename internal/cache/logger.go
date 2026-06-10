// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
)

var (
	// logger is read from arbitrary goroutines (cache mutators, TUI hosts)
	// while SetLoggerOutput/InitLogger may rebuild it concurrently, so it is
	// published via an atomic pointer rather than a bare global.
	logger     atomic.Pointer[slog.Logger]
	loggerMu   sync.Mutex
	loggerSink io.Writer = os.Stdout
)

func init() {
	// Ensure Logger is non-nil from package load so cache code paths that
	// fire before an explicit InitLogger() (e.g. during bootstrap) still log.
	InitLogger()
}

// SetLoggerOutput overrides the destination for cache log messages. Pass
// io.Discard from TUI hosts (apconsole) to keep log output from corrupting
// the bubbletea-managed display. Defaults to os.Stdout for standalone use.
// Affects subsequent InitLogger() calls and the active Logger if already built.
func SetLoggerOutput(w io.Writer) {
	if w == nil {
		w = os.Stdout
	}
	loggerMu.Lock()
	loggerSink = w
	loggerMu.Unlock()
	InitLogger()
}

// InitLogger initializes the global logger with appropriate log level
// Set APSHELL_DEBUG=1 environment variable to enable debug logging
func InitLogger() {
	level := slog.LevelInfo // Default: only show Info, Warn, Error

	// Check for debug mode
	if os.Getenv("APSHELL_DEBUG") != "" {
		level = slog.LevelDebug
	}

	loggerMu.Lock()
	sink := loggerSink
	loggerMu.Unlock()

	handler := slog.NewTextHandler(sink, &slog.HandlerOptions{
		Level: level,
		// Remove timestamp and other metadata for cleaner output
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Remove time attribute for cleaner CLI output
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			// Remove level attribute for cleaner CLI output
			if a.Key == slog.LevelKey {
				return slog.Attr{}
			}
			return a
		},
	})

	logger.Store(slog.New(handler))
}

// Debug logs a debug message (only shown when APSHELL_DEBUG is set)
func Debug(msg string, args ...any) {
	if l := logger.Load(); l != nil {
		l.Debug(msg, args...)
	}
}

// infof and warnf are package-internal helpers that route formatted text
// through the configured logger sink. They replace ad-hoc fmt.Print* calls
// inside cache mutators so TUI hosts (apconsole) can suppress these messages
// via SetLoggerOutput(io.Discard).
func infof(format string, args ...any) {
	if l := logger.Load(); l != nil {
		l.Info(fmt.Sprintf(format, args...))
	}
}

func warnf(format string, args ...any) {
	if l := logger.Load(); l != nil {
		l.Warn(fmt.Sprintf(format, args...))
	}
}
