// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"log/slog"

	"github.com/aplane-algo/aplane/internal/cmdlog"
)

var appLogger = cmdlog.New("apconsole")

func logInfof(format string, args ...any) {
	// apconsole is an interactive TUI; keep informational startup noise out of
	// the terminal unless it is rendered inside the console itself.
}

// logWarnf logs a startup diagnostic through the pipeline. Printed directly, it
// would be hidden as soon as the alternate screen opens; queued, it reaches the
// shell pane.
func logWarnf(format string, args ...any) {
	slog.Warn(fmt.Sprintf(format, args...), "component", "apconsole")
}

// logErrorf reports why apconsole can't continue. It stays a direct write, because
// a program's reason for stopping must not depend on a log level.
func logErrorf(format string, args ...any) {
	appLogger.Errorf(format, args...)
}
