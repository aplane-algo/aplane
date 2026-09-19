// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientenroll

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

// TokenClient is the client-owned token provisioning and persistence seam.
// The engine implementation disconnects an existing tunnel before requesting
// a replacement token and serializes token-file writes under the client lock.
type TokenClient interface {
	RequestTokenWithContext(
		ctx context.Context,
		host string,
		sshPort int,
		identityFile string,
		knownHostsPath string,
		hostKeyApproval sshtunnel.HostKeyApprovalHandler,
		onProvisioningStart func(string),
	) (string, error)
	SaveApshellTokenToPath(tokenPath, token string) (string, error)
}

// TokenRequestResult describes one endpoint-scoped token enrollment.
type TokenRequestResult struct {
	Alias     string
	TokenPath string
}

// RequestEndpointToken runs the existing synchronous SSH request-token
// protocol and stores the delivered bearer token only in client-owned state.
func RequestEndpointToken(
	ctx context.Context,
	client TokenClient,
	dataDir string,
	alias string,
	endpoint config.ClientEndpointConfig,
	hostKeyApproval sshtunnel.HostKeyApprovalHandler,
	onProvisioningStart func(string),
) (TokenRequestResult, error) {
	if client == nil {
		return TokenRequestResult{}, fmt.Errorf("token client is unavailable")
	}
	if alias == "" {
		return TokenRequestResult{}, fmt.Errorf("endpoint alias is required")
	}
	endpointSSH, err := config.ResolveClientEndpointSSH(endpoint)
	if err != nil {
		return TokenRequestResult{}, fmt.Errorf("resolve endpoint %q SSH configuration: %w", alias, err)
	}
	token, err := client.RequestTokenWithContext(
		ctx,
		endpointSSH.Host,
		endpointSSH.Port,
		endpointSSH.IdentityFile,
		endpointSSH.KnownHostsPath,
		hostKeyApproval,
		onProvisioningStart,
	)
	if err != nil {
		return TokenRequestResult{}, fmt.Errorf("request token from endpoint %q: %w", alias, err)
	}
	tokenPath := endpointSSH.TokenFile
	if tokenPath == "" {
		tokenPath, err = tokenfile.GetApshellTokenPathForDataDir(dataDir)
		if err != nil {
			return TokenRequestResult{}, err
		}
	}
	tokenPath, err = client.SaveApshellTokenToPath(tokenPath, token)
	if err != nil {
		return TokenRequestResult{}, fmt.Errorf("save token for endpoint %q: %w", alias, err)
	}
	return TokenRequestResult{Alias: alias, TokenPath: tokenPath}, nil
}
