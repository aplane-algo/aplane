// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package scripting runs JavaScript in an embedded Goja interpreter.
package scripting

// RunnerError represents an error that occurred during script execution.
type RunnerError struct {
	Message string
}

func (e *RunnerError) Error() string {
	return e.Message
}

// Result holds the outcome of running a script.
type Result struct {
	// Value is the exported result value (nil if IsEmpty is true)
	Value interface{}
	// IsEmpty is true if the script returned undefined/null/void
	IsEmpty bool
}
