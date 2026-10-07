// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import "github.com/aplane-algo/aplane/internal/config"

// StartupConnectDecision reports the app-layer startup decision for signer
// connectivity: connect when a default signer endpoint is configured. Whether
// this client's key is enrolled is known only to the node, so an unenrolled
// key is discovered as an authentication failure at connect time.
func (a *App) StartupConnectDecision() *StartupConnectDecision {
	registry := a.Config.ClientEndpointsOrDefault()
	alias, endpoint, ok := registry.DefaultEndpoint()
	decision := &StartupConnectDecision{EndpointName: alias}

	if ok {
		endpointSSH, err := config.ResolveClientEndpointSSH(endpoint)
		if err == nil {
			decision.HasSSHConfig = true
			decision.Host = endpointSSH.Host
			decision.SSHPort = endpointSSH.Port
		}
	}

	decision.ShouldConnect = decision.HasSSHConfig
	return decision
}
