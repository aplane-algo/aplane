// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import "github.com/aplane-algo/aplane/internal/cmdlog"

var appLogger = cmdlog.New("apconsole")

func logInfof(format string, args ...any) {
	// apconsole is an interactive TUI; keep informational startup noise out of
	// the terminal unless it is rendered inside the console itself.
}

func logWarnf(format string, args ...any) {
	appLogger.Warnf(format, args...)
}

func logErrorf(format string, args ...any) {
	appLogger.Errorf(format, args...)
}
