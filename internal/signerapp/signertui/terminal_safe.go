// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import "github.com/aplane-algo/aplane/internal/termsafe"

// Text the daemon, a template, a boundary file, an archive or the operator's
// disk supplied is escaped with terminalSafe or terminalSafeLines where a view
// lays it out, so its width is measured as shown and an SGR sequence in it is
// seen too. View passes the whole screen through terminalSafeScreen as well,
// which catches any such text a view does not escape.

// terminalSafe escapes s for printing on one line.
func terminalSafe(s string) string { return termsafe.Line(s) }

// terminalSafeLines escapes s for printing, keeping newlines and tabs.
func terminalSafeLines(s string) string { return termsafe.Lines(s) }

// terminalSafeScreen escapes a rendered screen, keeping its styling.
func terminalSafeScreen(s string) string { return termsafe.Screen(s) }
