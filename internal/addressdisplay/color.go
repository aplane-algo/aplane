// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package addressdisplay owns terminal-oriented address display helpers.
package addressdisplay

import (
	"fmt"
	"os"
	"sync"

	"golang.org/x/term"
)

// ColorFormatter provides color codes for key types.
type ColorFormatter func(keyType string) string

var (
	colorMu       sync.RWMutex
	colorOverride *bool
)

// SetColorSupported overrides terminal color detection. Use from TUI hosts
// where os.Stdout is redirected away from the TTY but rendered output still
// lands in a color-capable terminal. Pass false to force colors off; call
// ResetColorSupport to restore automatic detection.
func SetColorSupported(enabled bool) {
	colorMu.Lock()
	v := enabled
	colorOverride = &v
	colorMu.Unlock()
}

// ResetColorSupport clears any previous SetColorSupported override.
func ResetColorSupport() {
	colorMu.Lock()
	colorOverride = nil
	colorMu.Unlock()
}

// SupportsColor reports whether ANSI color output should be emitted.
func SupportsColor() bool {
	colorMu.RLock()
	override := colorOverride
	colorMu.RUnlock()
	if override != nil {
		return *override
	}

	if !term.IsTerminal(int(os.Stdout.Fd())) { // #nosec G115 - file descriptors are small integers
		return false
	}

	termEnv := os.Getenv("TERM")
	return termEnv != "" && termEnv != "dumb"
}

// FormatWithKeyColor formats text with ANSI color based on key type.
func FormatWithKeyColor(text string, keyType string, colorFormatter ColorFormatter) string {
	if !SupportsColor() || colorFormatter == nil {
		return text
	}

	colorCode := colorFormatter(keyType)
	if colorCode == "" {
		return text
	}

	return fmt.Sprintf("\033[%sm%s\033[0m", colorCode, text)
}
