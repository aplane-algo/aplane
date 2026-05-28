// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/command"
)

// toggleWriteMode enables/disables write mode for transaction JSON logging
func toggleWriteMode(r *REPLState, args []string) error {
	result, err := execWrite(r, args)
	if err != nil {
		return err
	}
	result.RenderText(r.Out, r)
	return nil
}

func execWrite(r *REPLState, args []string) (*ToggleResult, error) {
	if len(args) == 0 {
		return &ToggleResult{Toggle: r.app().WriteMode()}, nil
	} else if len(args) == 1 {
		mode := strings.ToLower(args[0])
		switch mode {
		case "on", "true", "1":
			toggle, err := r.app().SetWriteMode(true)
			if err != nil {
				r.printf("Warning: failed to create txnjson directory: %v\n", err)
			} else {
				return &ToggleResult{Toggle: toggle}, nil
			}
		case "off", "false", "0":
			return &ToggleResult{Toggle: mustSetWriteModeOff(r)}, nil
		default:
			return nil, fmt.Errorf("usage: write [on|off]")
		}
	} else {
		return nil, fmt.Errorf("usage: write [on|off]")
	}

	return &ToggleResult{Toggle: r.app().WriteMode()}, nil
}

// toggleVerbose enables/disables detailed signing output
func execVerbose(r *REPLState, args []string) (*ToggleResult, error) {
	if len(args) == 0 {
		return &ToggleResult{Toggle: r.app().VerboseMode()}, nil
	}
	if len(args) != 1 {
		return nil, fmt.Errorf("usage: verbose [on|off]")
	}
	mode := strings.ToLower(args[0])
	switch mode {
	case "on", "true", "1":
		return &ToggleResult{Toggle: r.app().SetVerboseMode(true)}, nil
	case "off", "false", "0":
		return &ToggleResult{Toggle: r.app().SetVerboseMode(false)}, nil
	default:
		return nil, fmt.Errorf("usage: verbose [on|off]")
	}
}

// toggleSimulate enables/disables transaction simulation mode, or executes
// a one-shot simulated command: simulate send 5 algo from alice to bob
func toggleSimulate(r *REPLState, args []string) error {
	if len(args) == 0 {
		// Show current state
		if r.app().IsSimulateEnabled() {
			r.println("Simulate mode: on")
		} else {
			r.println("Simulate mode: off")
		}
		return nil
	}

	// Check for on/off toggle (single arg only)
	if len(args) == 1 {
		switch strings.ToLower(args[0]) {
		case "on", "true", "1":
			r.app().SetSimulateMode(true)
			r.println("✓ Simulate mode enabled - transactions will be simulated, not submitted")
			return nil
		case "off", "false", "0":
			r.app().SetSimulateMode(false)
			r.println("✓ Simulate mode disabled")
			return nil
		}
	}

	if registeredCmd, ok := r.CommandRegistry.Lookup(args[0]); ok && registeredCmd.Category != command.CategoryTransaction {
		return fmt.Errorf("simulate only supports transaction commands")
	}

	// One-shot simulate: treat args as a transaction command to execute with simulate on
	prev := r.app().IsSimulateEnabled()
	r.app().SetSimulateMode(true)
	defer func() { r.app().SetSimulateMode(prev) }()

	cmd := Command{
		Name:    args[0],
		Args:    args[1:],
		RawArgs: strings.Join(args[1:], " "),
	}
	return r.executeCommand(cmd)
}

func mustSetWriteModeOff(r *REPLState) appresult.Toggle {
	toggle, _ := r.app().SetWriteMode(false)
	return toggle
}
