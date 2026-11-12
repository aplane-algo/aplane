// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import "log/slog"

// logger returns the engine's logger. It is made at each call, because a
// logger kept from package initialization would miss the handler the host
// installs.
func logger() *slog.Logger {
	return slog.With("component", "engine")
}
