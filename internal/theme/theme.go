// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package theme provides terminal color palette management with dark/light
// background detection. Colors are selected based on terminal background
// to ensure readability across different terminal configurations.
package theme

import (
	"os"
	"strings"
	"sync"

	"github.com/charmbracelet/lipgloss"
)

// Palette holds ANSI color codes for a specific terminal background.
type Palette struct {
	// Algorithm key type colors (ANSI codes for raw escape sequences)
	Ed25519Color string // Color for ed25519 addresses/labels
	FalconColor  string // Color for falcon1024 addresses/labels
	DefaultColor string // Fallback for unknown key types
	AliasColor   string // Color for alias names
	PromptColor  string // Color for shell prompt

	// Lipgloss 256-color codes (for apadmin TUI styles)
	Title              string // Title text
	Subtitle           string // Subdued text, help bar
	StatusConnected    string // Connected/unlocked indicator
	StatusDisconnected string // Disconnected/error indicator
	StatusLocked       string // Warning/locked indicator
	InputBorder        string // Default input border
	InputActive        string // Active input border
	InputInactive      string // Inactive input border
	Error              string // Error text
	Warning            string // Warning text
	Help               string // Help text
	Selected           string // Selected item background
	SelectedFg         string // Selected item foreground
	Button             string // Active button
	ButtonInactive     string // Inactive button
	Popup              string // Popup border
	KeyType            string // Key type label default
}

// Dark palette — optimized for dark terminal backgrounds (default for most developers)
var Dark = Palette{
	Ed25519Color: "36", // Cyan
	FalconColor:  "33", // Yellow
	DefaultColor: "39", // Default terminal foreground
	AliasColor:   "36", // Cyan
	PromptColor:  "33", // Yellow

	Title:              "205", // Magenta
	Subtitle:           "241", // Dark gray
	StatusConnected:    "42",  // Green
	StatusDisconnected: "196", // Red
	StatusLocked:       "214", // Orange
	InputBorder:        "62",  // Blue/purple
	InputActive:        "42",  // Green
	InputInactive:      "241", // Gray
	Error:              "196", // Red
	Warning:            "214", // Orange
	Help:               "241", // Gray
	Selected:           "62",  // Blue/purple background
	SelectedFg:         "255", // White
	Button:             "42",  // Green
	ButtonInactive:     "241", // Gray
	Popup:              "214", // Orange
	KeyType:            "39",  // Cyan
}

// Light palette — optimized for light terminal backgrounds (macOS Terminal default, etc.)
var Light = Palette{
	Ed25519Color: "30", // Dark cyan (teal)
	FalconColor:  "94", // Dark yellow/brown
	DefaultColor: "39", // Default terminal foreground
	AliasColor:   "30", // Dark cyan
	PromptColor:  "28", // Dark green

	Title:              "125", // Dark magenta
	Subtitle:           "243", // Medium gray
	StatusConnected:    "28",  // Dark green
	StatusDisconnected: "160", // Dark red
	StatusLocked:       "130", // Dark orange
	InputBorder:        "61",  // Dark purple
	InputActive:        "28",  // Dark green
	InputInactive:      "243", // Medium gray
	Error:              "160", // Dark red
	Warning:            "130", // Dark orange
	Help:               "243", // Medium gray
	Selected:           "61",  // Dark purple background
	SelectedFg:         "255", // White
	Button:             "28",  // Dark green
	ButtonInactive:     "243", // Medium gray
	Popup:              "130", // Dark orange
	KeyType:            "30",  // Dark cyan
}

var (
	current     *Palette
	currentOnce sync.Once
	mu          sync.Mutex
)

// Init initializes the theme based on the given mode ("auto", "dark", "light").
// Should be called once at startup. Safe to call multiple times (last call wins).
func Init(mode string) {
	mu.Lock()
	defer mu.Unlock()

	switch strings.ToLower(mode) {
	case "light":
		current = &Light
	case "dark":
		current = &Dark
	default: // "auto" or empty
		current = detect()
	}
}

// Current returns the active palette. If Init hasn't been called, auto-detects.
func Current() *Palette {
	mu.Lock()
	defer mu.Unlock()

	if current == nil {
		currentOnce.Do(func() {
			current = detect()
		})
	}
	return current
}

// IsDark returns true if the current palette is for dark backgrounds.
func IsDark() bool {
	return Current() == &Dark
}

// detect queries the terminal background color and returns the appropriate palette.
func detect() *Palette {
	// Skip detection if not a terminal (e.g., piped output, CI)
	if os.Getenv("TERM") == "" || os.Getenv("TERM") == "dumb" {
		return &Dark // Default to dark when we can't detect
	}

	// lipgloss queries the terminal via OSC 11 (background color request)
	if lipgloss.HasDarkBackground() {
		return &Dark
	}
	return &Light
}
