// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/apshellapp"
)

// setNetwork changes the active network context token.
func setNetwork(r *REPLState, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: network <network>")
	}

	res, err := r.app().SwitchNetwork(r.commandContext(), apshellapp.SwitchNetworkRequest{
		Network: args[0],
	})
	if err != nil {
		return err
	}

	return r.renderSwitchNetworkResult(res)
}
