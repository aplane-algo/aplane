// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import "github.com/aplane-algo/aplane/internal/cmdlog"

var appLogger = cmdlog.New("apadmin")

func logInfof(format string, args ...any) {
	// apadmin is primarily an interactive TUI; keep startup/status noise out of
	// the terminal unless it is warning or error level.
}

func logWarnf(format string, args ...any) {
	appLogger.Warnf(format, args...)
}

func logErrorf(format string, args ...any) {
	appLogger.Errorf(format, args...)
}
