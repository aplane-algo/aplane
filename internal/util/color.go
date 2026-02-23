// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// ColorFormatter provides a function type for getting color codes by key type
type ColorFormatter func(keyType string) string

// supportsColor checks if the terminal supports ANSI color codes
func supportsColor() bool {
	// Check if stdout is a terminal
	if !term.IsTerminal(int(os.Stdout.Fd())) { // #nosec G115 - file descriptors are small integers
		return false
	}

	// Check TERM environment variable
	termEnv := os.Getenv("TERM")
	if termEnv == "" || termEnv == "dumb" {
		return false
	}

	return true
}

// FormatAddressWithColor formats an address with ANSI color based on key type
// Uses the provided colorFormatter function to get the color code
func FormatAddressWithColor(address string, keyType string, colorFormatter ColorFormatter) string {
	if !supportsColor() || colorFormatter == nil {
		return address
	}

	colorCode := colorFormatter(keyType)
	if colorCode == "" {
		return address
	}

	return fmt.Sprintf("\033[%sm%s\033[0m", colorCode, address)
}
