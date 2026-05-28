// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import "github.com/aplane-algo/aplane/internal/scripting"

// ScriptSession holds mutable state for JavaScript execution.
type ScriptSession struct {
	Runner   scripting.Runner
	LastCode string // last successfully executed JavaScript code
}
