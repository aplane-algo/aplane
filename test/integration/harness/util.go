// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package harness

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// findProjectRoot finds the project root by looking for go.mod
func findProjectRoot() (string, error) {
	// Start from current directory and walk up
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		// Check if go.mod exists in this directory
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}

		// Move up one directory
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root without finding go.mod
			break
		}
		dir = parent
	}

	// Fallback: try git rev-parse
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	output, err := cmd.Output()
	if err == nil {
		return strings.TrimSpace(string(output)), nil
	}

	return "", fmt.Errorf("could not find project root (no go.mod found)")
}
