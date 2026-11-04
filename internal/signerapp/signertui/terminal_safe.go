// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import "github.com/aplane-algo/aplane/internal/termsafe"

// terminalSafe escapes s for printing on one line.
func terminalSafe(s string) string { return termsafe.Line(s) }

// terminalSafeLines escapes s for printing, keeping newlines and tabs.
func terminalSafeLines(s string) string { return termsafe.Lines(s) }
