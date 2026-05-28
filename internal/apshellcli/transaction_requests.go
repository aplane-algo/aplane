// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/shellrepl"
)

func optOutRequestFromParams(params shellrepl.OptOutParams) apshellapp.OptOutRequest {
	return apshellapp.OptOutRequest{
		Account:    params.Account,
		AssetRef:   params.ASARef.String(),
		CloseTo:    params.CloseTo,
		Fee:        params.Fee,
		UseFlatFee: params.UseFlatFee,
		Wait:       params.Wait,
	}
}

func closeRequestFromParams(params shellrepl.CloseParams) apshellapp.CloseRequest {
	return apshellapp.CloseRequest{
		Account:    params.Account,
		CloseTo:    params.CloseTo,
		Fee:        params.Fee,
		UseFlatFee: params.UseFlatFee,
		LsigArgs:   params.LsigArgs,
		Wait:       params.Wait,
	}
}
