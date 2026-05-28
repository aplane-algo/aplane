// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Send command implementations for ALGO and ASA transfers.
// Supports single, set-based, and atomic transaction groups.

import (
	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/shellrepl"
)

func (r *REPLState) runSend(args []string) error {
	params, err := shellrepl.ParseSendCommand(args)
	if err != nil {
		return err
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
		return err
	}
	return r.renderSendResult(result)
}
