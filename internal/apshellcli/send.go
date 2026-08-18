// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Send command implementations for ALGO and ASA transfers.
// Supports single, set-based, and atomic transaction groups.

import (
	"io"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/shellrepl"
)

func (r *REPLState) runSend(args []string) (command.Result, error) {
	params, err := shellrepl.ParseSendCommand(args)
	if err != nil {
		return nil, err
	}

	result, err := r.app().ExecuteSend(r.commandContext(), apshellapp.SendRequest{
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
	})
	if err != nil {
		return nil, err
	}
	simulated := r.app().IsSimulateEnabled()
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutputResult(w, func() error { return r.renderSendResult(result) })
	}, projectSendResult(result, simulated))
}
