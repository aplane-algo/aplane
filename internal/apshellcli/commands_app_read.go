// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import "github.com/aplane-algo/aplane/internal/apshellapp"

func execAppRead(r *REPLState, args []string) (*JSONResult, error) {
	result, err := r.app().AppRead(r.commandContext(), apshellapp.AppReadRequest{Args: args})
	if err != nil {
		return nil, err
	}
	return &JSONResult{Data: result.Data}, nil
}
