// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/command"
)

func execWrite(r *REPLState, args []string) (toggleOutcome, error) {
	if len(args) == 0 {
		return toggleOutcome{Toggle: r.app().WriteMode()}, nil
	} else if len(args) == 1 {
		mode := strings.ToLower(args[0])
		switch mode {
		case "on", "true", "1":
			toggle, err := r.app().SetWriteMode(true)
			if err != nil {
				return toggleOutcome{
					Toggle:  r.app().WriteMode(),
					Warning: fmt.Sprintf("failed to create txnjson directory: %v", err),
				}, nil
			} else {
				return toggleOutcome{Toggle: toggle}, nil
			}
		case "off", "false", "0":
			return toggleOutcome{Toggle: mustSetWriteModeOff(r)}, nil
		default:
			return toggleOutcome{}, fmt.Errorf("usage: write [on|off]")
		}
	} else {
		return toggleOutcome{}, fmt.Errorf("usage: write [on|off]")
	}
}

// toggleVerbose enables/disables detailed signing output
func execVerbose(r *REPLState, args []string) (toggleOutcome, error) {
	if len(args) == 0 {
		return toggleOutcome{Toggle: r.app().VerboseMode()}, nil
	}
	if len(args) != 1 {
		return toggleOutcome{}, fmt.Errorf("usage: verbose [on|off]")
	}
	mode := strings.ToLower(args[0])
	switch mode {
	case "on", "true", "1":
		return toggleOutcome{Toggle: r.app().SetVerboseMode(true)}, nil
	case "off", "false", "0":
		return toggleOutcome{Toggle: r.app().SetVerboseMode(false)}, nil
	default:
		return toggleOutcome{}, fmt.Errorf("usage: verbose [on|off]")
	}
}

// toggleSimulate enables/disables transaction simulation mode, or executes
// a one-shot simulated command: simulate send 5 algo from alice to bob
func executeSimulate(r *REPLState, args []string) (command.Result, error) {
	if len(args) == 0 {
		enabled := r.app().IsSimulateEnabled()
		return newShellCommandResult(func(w io.Writer) error {
			state := "off"
			if enabled {
				state = "on"
			}
			_, err := fmt.Fprintf(w, "Simulate mode: %s\n", state)
			return err
		}, struct {
			Name    string `json:"name"`
			Enabled bool   `json:"enabled"`
		}{Name: "simulate", Enabled: enabled})
	}

	// Check for on/off toggle (single arg only)
	if len(args) == 1 {
		switch strings.ToLower(args[0]) {
		case "on", "true", "1":
			r.app().SetSimulateMode(true)
			return newShellCommandResult(func(w io.Writer) error {
				_, err := fmt.Fprintln(w, "✓ Simulate mode enabled - transactions will be simulated, not submitted")
				return err
			}, struct {
				Name    string `json:"name"`
				Enabled bool   `json:"enabled"`
			}{Name: "simulate", Enabled: true})
		case "off", "false", "0":
			r.app().SetSimulateMode(false)
			return newShellCommandResult(func(w io.Writer) error {
				_, err := fmt.Fprintln(w, "✓ Simulate mode disabled")
				return err
			}, struct {
				Name    string `json:"name"`
				Enabled bool   `json:"enabled"`
			}{Name: "simulate", Enabled: false})
		}
	}

	if registeredCmd, ok := r.CommandRegistry.Lookup(args[0]); ok && registeredCmd.Category != command.CategoryTransaction {
		return nil, fmt.Errorf("simulate only supports transaction commands")
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
	result, err := r.executeCommandResult(cmd)
	if err != nil {
		return result, err
	}
	if result == nil {
		return nil, fmt.Errorf("simulated command returned no result")
	}
	data, err := result.MarshalMachine()
	if err != nil {
		return nil, err
	}
	if !json.Valid(data) {
		return nil, fmt.Errorf("simulated command returned invalid JSON")
	}
	wrapped, err := newShellCommandJSONResult(func(w io.Writer) error {
		return result.RenderText(w)
	}, data)
	if err != nil {
		return nil, err
	}
	if terminal, ok := result.(interface{ terminalFailure() error }); ok {
		wrapped.(*shellCommandResult).terminalErr = terminal.terminalFailure()
	}
	return wrapped, nil
}

func mustSetWriteModeOff(r *REPLState) appresult.Toggle {
	toggle, _ := r.app().SetWriteMode(false)
	return toggle
}
