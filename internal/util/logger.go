// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"log/slog"
	"os"
)

var Logger *slog.Logger

// InitLogger initializes the global logger with appropriate log level
// Set APSHELL_DEBUG=1 environment variable to enable debug logging
func InitLogger() {
	level := slog.LevelInfo // Default: only show Info, Warn, Error

	// Check for debug mode
	if os.Getenv("APSHELL_DEBUG") != "" {
		level = slog.LevelDebug
	}

	// Create a text handler that writes to stdout
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
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

	Logger = slog.New(handler)
}

// Debug logs a debug message (only shown when APSHELL_DEBUG is set)
func Debug(msg string, args ...any) {
	Logger.Debug(msg, args...)
}
