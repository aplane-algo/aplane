// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"fmt"
	"os"
	"strings"
)

// toggleWriteMode enables/disables write mode for transaction JSON logging
func (r *REPLState) toggleWriteMode(args []string) error {
	if len(args) == 0 {
		// Show current state
		if r.Engine.WriteMode {
			fmt.Println("Write mode: on")
		} else {
			fmt.Println("Write mode: off")
		}
		return nil
	} else if len(args) == 1 {
		// Set explicitly
		mode := strings.ToLower(args[0])
		switch mode {
		case "on", "true", "1":
			r.Engine.WriteMode = true
			fmt.Println("✓ Write mode enabled - transactions will be saved to txnjson/")
			if err := os.MkdirAll("txnjson", 0750); err != nil {
				fmt.Printf("Warning: failed to create txnjson directory: %v\n", err)
			}
		case "off", "false", "0":
			r.Engine.WriteMode = false
			fmt.Println("✓ Write mode disabled")
		default:
			return fmt.Errorf("usage: write [on|off]")
		}
	} else {
		return fmt.Errorf("usage: write [on|off]")
	}

	return nil
}

// toggleVerbose enables/disables detailed signing output
func (r *REPLState) toggleVerbose(args []string) error {
	if len(args) == 0 {
		// Show current state
		if r.Engine.Verbose {
			fmt.Println("Verbose mode: on")
		} else {
			fmt.Println("Verbose mode: off")
		}
		return nil
	} else if len(args) == 1 {
		// Set explicitly
		mode := strings.ToLower(args[0])
		switch mode {
		case "on", "true", "1":
			r.Engine.Verbose = true
			fmt.Println("✓ Verbose mode enabled - detailed signing output will be shown")
		case "off", "false", "0":
			r.Engine.Verbose = false
			fmt.Println("✓ Verbose mode disabled")
		default:
			return fmt.Errorf("usage: verbose [on|off]")
		}
	} else {
		return fmt.Errorf("usage: verbose [on|off]")
	}

	return nil
}

// toggleSimulate enables/disables transaction simulation mode, or executes
// a one-shot simulated command: simulate send 5 algo from alice to bob
func (r *REPLState) toggleSimulate(args []string) error {
	if len(args) == 0 {
		// Show current state
		if r.Engine.Simulate {
			fmt.Println("Simulate mode: on")
		} else {
			fmt.Println("Simulate mode: off")
		}
		return nil
	}

	// Check for on/off toggle (single arg only)
	if len(args) == 1 {
		switch strings.ToLower(args[0]) {
		case "on", "true", "1":
			r.Engine.Simulate = true
			fmt.Println("✓ Simulate mode enabled - transactions will be simulated, not submitted")
			return nil
		case "off", "false", "0":
			r.Engine.Simulate = false
			fmt.Println("✓ Simulate mode disabled")
			return nil
		}
	}

	// One-shot simulate: treat args as a command to execute with simulate on
	prev := r.Engine.Simulate
	r.Engine.Simulate = true
	defer func() { r.Engine.Simulate = prev }()

	cmd := Command{
		Name:    args[0],
		Args:    args[1:],
		RawArgs: strings.Join(args[1:], " "),
	}
	return r.executeCommand(cmd)
}
