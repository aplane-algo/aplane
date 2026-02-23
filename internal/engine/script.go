// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package engine

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// CommandExecutor is a function that executes a parsed command.
// This allows the REPL to inject its command execution logic.
type CommandExecutor func(cmdName string, args []string) error

// RunScript executes commands from a script file.
// The executor callback is provided by the REPL layer to handle actual command execution.
func (e *Engine) RunScript(filepath string, executor CommandExecutor) (*ScriptResult, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open script: %w", err)
	}
	defer func() { _ = file.Close() }()

	result := &ScriptResult{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		result.LinesExecuted++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse command and args
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		cmdName := parts[0]
		args := parts[1:]
		result.CommandsRun++

		// Execute via injected executor
		if err := executor(cmdName, args); err != nil {
			// Check for exit command
			if err.Error() == "exit" {
				result.Completed = true
				return result, err
			}

			result.Errors = append(result.Errors, ScriptError{
				LineNumber: result.LinesExecuted,
				Command:    line,
				Error:      err.Error(),
			})
			// Stop on first error
			return result, fmt.Errorf("%w at line %d: %v", ErrScriptError, result.LinesExecuted, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return result, fmt.Errorf("error reading script: %w", err)
	}

	result.Completed = true
	return result, nil
}
