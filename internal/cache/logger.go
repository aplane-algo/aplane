// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"fmt"
	"log/slog"
)

// logger returns the cache's logger. It is made at each call, because a logger
// kept from package initialization would miss the handler the host installs.
func logger() *slog.Logger {
	return slog.With("component", "cache")
}

// Debug logs a debug message. Other packages use it for cache-related detail.
func Debug(msg string, args ...any) {
	logger().Debug(msg, args...)
}

func infof(format string, args ...any) {
	logger().Info(fmt.Sprintf(format, args...))
}

func warnf(format string, args ...any) {
	logger().Warn(fmt.Sprintf(format, args...))
}
