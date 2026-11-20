// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Send command implementations for ALGO and ASA transfers.
// Supports single, set-based, and atomic transaction groups.

import (
	"errors"
	"fmt"
	"io"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/shellrepl"
)

// cmdSend handles the send command for ALGO or ASA transfers.
func (r *REPLState) cmdSend(args []string, _ *command.Context) (command.Result, error) {
	params, err := shellrepl.ParseSendCommand(args)
	if err != nil {
		return nil, err
	}

	req := apshellapp.SendRequest{
		AmountText: params.Amount.String(),
		AssetRef:   params.Asset.String(),
		FromRaw:    params.FromRaw,
		ToRaw:      params.ToRaw,
		Note:       params.Note,
		Wait:       params.Wait,
		Atomic:     params.Atomic,
		Fee:        params.Fee,
		UseFlatFee: params.UseFlatFee,
		LsigArgs:   params.LsigArgs,
	}
	// A person at the prompt is asked about a lookalike recipient before
	// anything is signed. Without one (MCP, scripts) the send goes on, and
	// its result carries the warning.
	if !r.AutoConfirm {
		req.ConfirmLookalikes = r.confirmLookalikes
	}
	result, err := r.app().ExecuteSend(r.commandContext(), req)
	if errors.Is(err, apshellapp.ErrLookalikeDeclined) {
		return newShellCommandResult(func(w io.Writer) error {
			_, err := fmt.Fprintln(w, "Cancelled.")
			return err
		}, sendProjection{Cancelled: true})
	}
	// A non-atomic send in which every item failed comes back with its
	// result and an error, as a sweep does: the items are drawn, and the
	// command fails.
	if err != nil && result == nil {
		return nil, err
	}
	simulated := r.app().IsSimulateEnabled()
	commandResult, resultErr := newShellCommandResult(func(w io.Writer) error {
		return r.withOutputResult(w, func() error {
			if req.ConfirmLookalikes == nil {
				r.renderWarnings(result.Warnings)
			}
			return r.renderSendResult(result, simulated)
		})
	}, projectSendResult(result, simulated))
	if resultErr != nil {
		return nil, resultErr
	}
	return commandResult, err
}

// confirmLookalikes shows each recipient that looks like a known account and
// asks whether to send anyway. The answer defaults to no.
func (r *REPLState) confirmLookalikes(lookalikes []apshellapp.RecipientLookalike) (bool, error) {
	for _, lookalike := range lookalikes {
		r.printf("⚠️  Warning: %s\n", lookalike.Message())
	}
	response, err := r.readPromptResponse("Send anyway? [y/N]: ")
	if err != nil {
		return false, err
	}
	return response == "y" || response == "yes", nil
}
