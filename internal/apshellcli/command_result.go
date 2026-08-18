// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/aplane-algo/aplane/internal/command"
)

// shellCommandResult contains an already-computed command outcome. Its
// renderers are presentation-only and may be called repeatedly.
type shellCommandResult struct {
	render      func(io.Writer) error
	machine     []byte
	terminalErr error
}

var _ command.Result = (*shellCommandResult)(nil)

func newShellCommandResult(render func(io.Writer) error, projection interface{}) (command.Result, error) {
	data, err := json.Marshal(projection)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal command result: %w", err)
	}
	return newShellCommandJSONResult(render, data)
}

func newShellCommandJSONResult(render func(io.Writer) error, data []byte) (command.Result, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("structured command returned an empty machine result")
	}
	if !json.Valid(data) {
		return nil, fmt.Errorf("structured command returned invalid JSON")
	}
	return &shellCommandResult{render: render, machine: append([]byte(nil), data...)}, nil
}

func newTerminalCommandResult(render func(io.Writer) error) command.Result {
	return &shellCommandResult{render: render}
}

func (r *shellCommandResult) RenderText(w io.Writer) error {
	if r == nil || r.render == nil {
		return nil
	}
	return r.render(w)
}

func (r *shellCommandResult) MarshalMachine() ([]byte, error) {
	if r == nil || len(r.machine) == 0 {
		return nil, fmt.Errorf("command has no machine result")
	}
	return append([]byte(nil), r.machine...), nil
}

func (r *shellCommandResult) terminalFailure() error {
	return r.terminalErr
}

func (r *REPLState) withOutput(w io.Writer, fn func()) error {
	return r.withOutputResult(w, func() error {
		fn()
		return nil
	})
}

func (r *REPLState) withOutputResult(w io.Writer, fn func() error) error {
	previous := r.Out
	r.SetOutput(w)
	defer r.SetOutput(previous)
	return fn()
}
