// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"
	"os"
	"strings"
)

// runScript executes REPL commands from a file, line by line
func (r *REPLState) runScript(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: script <file>")
	}

	filepath := args[0]

	// Read the file
	data, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("failed to read script file: %w", err)
	}

	// Split into lines
	lines := strings.Split(string(data), "\n")

	r.printf("Executing script: %s (%d lines)\n\n", filepath, len(lines))

	executed := 0
	for lineNum, line := range lines {
		// Trim whitespace
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Print the command being executed
		r.printf("[%d] %s\n", lineNum+1, line)

		// Parse and execute the command
		cmd, err := parseShellCommand(line)
		if err != nil {
			r.printf("Error on line %d: %v\n", lineNum+1, err)
			return fmt.Errorf("script execution stopped at line %d", lineNum+1)
		}
		if cmd.Name == "" {
			continue
		}
		err = r.executeCommand(cmd)

		if err != nil {
			// Check if it's an exit command
			if err.Error() == "exit" {
				return err
			}
			r.printf("Error on line %d: %v\n", lineNum+1, err)
			return fmt.Errorf("script execution stopped at line %d", lineNum+1)
		}

		executed++
	}

	r.printf("\n✓ Script completed successfully (%d commands executed)\n", executed)
	return nil
}
