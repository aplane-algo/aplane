// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import "github.com/aplane-algo/aplane/internal/apshellapp"

func (r *REPLState) renderSwitchNetworkResult(res *apshellapp.SwitchNetworkResult) error {
	r.printf("%s\n", res.Summary.Message)
	return nil
}
