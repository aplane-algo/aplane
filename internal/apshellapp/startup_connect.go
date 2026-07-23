// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

// StartupConnectDecision reports the app-layer startup decision for signer connectivity.
func (a *App) StartupConnectDecision() *StartupConnectDecision {
	registry := a.Config.ClientEndpointsOrDefault()
	alias, endpoint, ok := registry.DefaultEndpoint()
	tokenPath := endpoint.TokenFile
	if tokenPath == "" {
		tokenPath, _ = tokenfile.GetApshellTokenPathForDataDir(a.DataDir)
	}
	token, _ := tokenfile.ReadToken(tokenPath)
	decision := &StartupConnectDecision{
		EndpointName: alias,
		HasToken:     token != "",
		TokenPath:    tokenPath,
	}

	if ok {
		endpointSSH, err := config.ResolveClientEndpointSSH(endpoint)
		if err == nil {
			decision.HasSSHConfig = true
			decision.Host = endpointSSH.Host
			decision.SSHPort = endpointSSH.Port
			decision.SignerPort = endpointSSH.SignerPort
		}
	}

	decision.ShouldConnect = decision.HasToken && decision.HasSSHConfig
	return decision
}
