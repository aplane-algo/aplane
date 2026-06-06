// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import "github.com/aplane-algo/aplane/internal/tokenfile"

// StartupConnectDecision reports the app-layer startup decision for signer connectivity.
func (a *App) StartupConnectDecision() *StartupConnectDecision {
	registry := a.Config.ClientEndpointsOrDefault(a.DataDir)
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
		host, sshPort, err := sshEndpointHostPort(endpoint)
		if err == nil {
			signerPort := endpoint.SignerPort
			if signerPort == 0 {
				signerPort = a.Config.LegacySignerPort
			}
			decision.HasSSHConfig = true
			decision.Host = host
			decision.SSHPort = sshPort
			decision.SignerPort = signerPort
		}
	}

	decision.ShouldConnect = decision.HasToken && decision.HasSSHConfig
	return decision
}
