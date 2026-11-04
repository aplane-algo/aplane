// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Command logreach is the negative control for logging-reach-check: a program that
// can log, which the check must report as such. It shows the check is able to fail.
package main

import "log/slog"

func main() {
	slog.Warn("logging reach control")
}
