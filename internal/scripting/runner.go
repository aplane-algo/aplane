// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package scripting provides interfaces and implementations for script execution.
// It abstracts the underlying VM (Goja, Starlark, etc.) behind a common interface.
package scripting

// ScriptError represents an error that occurred during script execution.
type ScriptError struct {
	Message string
}

func (e *ScriptError) Error() string {
	return e.Message
}

// Result holds the outcome of running a script.
type Result struct {
	// Value is the exported result value (nil if IsEmpty is true)
	Value interface{}
	// IsEmpty is true if the script returned undefined/null/void
	IsEmpty bool
}

// Runner is the low-level VM abstraction for executing scripts.
// It handles code execution within an embedded interpreter.
//
// This interface is designed for:
//   - REPL usage (persistent runtime, line-by-line execution)
//   - Swappable engines (Goja, Starlark, etc.)
//
// It does NOT handle:
//   - File I/O (loading scripts from disk)
//   - Timeouts or context cancellation
//   - Job/task semantics
//
// For those concerns, see ScriptExecutor (higher-level abstraction).
type Runner interface {
	// Run executes the given code and returns the result.
	// Errors include syntax errors, runtime exceptions, etc.
	Run(code string) (Result, error)

	// SetOutput sets the function used for print() output.
	// Must be called before Run() if custom output handling is needed.
	SetOutput(fn func(string))

	// Interrupt stops the currently running script.
	// Safe to call from another goroutine.
	Interrupt()
}
