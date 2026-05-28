// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import "github.com/aplane-algo/aplane/internal/tokenfile"

// StartupConnectDecision reports the app-layer startup decision for signer connectivity.
func (a *App) StartupConnectDecision() *StartupConnectDecision {
	token, _ := tokenfile.LoadApshellTokenFromDataDir(a.DataDir)
	decision := &StartupConnectDecision{
		HasToken:  token != "",
		TokenPath: getTokenPathDescription(a.DataDir),
	}

	if a.Config.SSH != nil {
		decision.HasSSHConfig = true
		decision.Host = a.Config.SSH.Host
		decision.SSHPort = a.Config.SSH.Port
		decision.SignerPort = a.Config.SignerPort
	}

	decision.ShouldConnect = decision.HasToken && decision.HasSSHConfig
	return decision
}
