// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import "github.com/aplane-algo/aplane/internal/apshellapp"

func (r *REPLState) renderConnectResult(res *apshellapp.ConnectResult) error {
	for _, line := range res.RenderLines {
		r.println(line)
	}
	return nil
}
