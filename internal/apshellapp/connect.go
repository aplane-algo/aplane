// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/aplane-algo/aplane/internal/clientenroll"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	engineconnect "github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

// isAuthenticationFailure reports whether a connect error is an
// authentication problem: an HTTP 401 from the signer (typed) or an SSH
// public-key auth rejection (x/crypto/ssh exposes no typed error, so that
// case still matches the standard "unable to authenticate" text).
func isAuthenticationFailure(err error) bool {
	var herr *signerclient.HTTPStatusError
	if errors.As(err, &herr) {
		return herr.StatusCode == http.StatusUnauthorized
	}
	return strings.Contains(err.Error(), "unable to authenticate")
}

// ConnectRequest establishes an SSH tunnel to the signer.
type ConnectRequest struct {
	Host            string
	SSHPort         int
	IdentityFile    string
	KnownHostsPath  string
	TokenFile       string
	EndpointName    string
	HostKeyApproval sshtunnel.HostKeyApprovalHandler
	OnDisconnect    func()
}

// Connect establishes an SSH tunnel using the configured signer identity and token.
func (a *App) Connect(_ context.Context, req ConnectRequest) (*ConnectResult, error) {
	tokenPath, err := a.tokenPathForRequest(req.TokenFile)
	if err != nil {
		return nil, err
	}
	token, _ := tokenfile.ReadToken(tokenPath)
	if token == "" {
		return nil, fmt.Errorf("no token configured.\nRun 'request-token' to obtain a token, or copy a token to %s", tokenPath)
	}

	localPort, err := engineconnect.FindAvailableLocalPort()
	if err != nil {
		return nil, fmt.Errorf("failed to find available local port: %w", err)
	}

	target := fmt.Sprintf("%s (ssh:%d)", req.Host, req.SSHPort)
	connectResult, err := a.eng.ConnectWithTunnel(
		target,
		req.Host,
		req.SSHPort,
		localPort,
		token,
		req.IdentityFile,
		req.KnownHostsPath,
		req.HostKeyApproval,
		req.OnDisconnect,
	)
	if err != nil {
		if isAuthenticationFailure(err) {
			return nil, fmt.Errorf("authentication failed — possible causes:\n  - Token at %s was revoked or is invalid\n  - SSH key is not in the signer's authorized_keys\n\nTry 'request-token' to re-enroll, or copy a valid aplane.token from the signer", tokenPath)
		}
		return nil, err
	}
	result := connectionDetailsFromEngine(connectResult)

	res := &ConnectResult{
		Target:   target,
		Port:     result.Port,
		KeyCount: result.KeyCount,
		Locked:   result.Locked,
	}

	if result.Connected && result.Port == 0 {
		res.AlreadyConnected = true
		res.Summary = Summary{Message: fmt.Sprintf("Already connected to %s", target)}
		decorateConnectResult(res)
		return res, nil
	}

	res.Summary = Summary{Message: fmt.Sprintf("Signer verified via tunnel at http://localhost:%d", result.Port)}
	if result.Locked {
		res.Warnings = append(res.Warnings, Warning{
			Code:    "signer_locked",
			Message: "Signer is locked — unlock via apadmin before signing",
		})
	}
	decorateConnectResult(res)
	return res, nil
}

// ConnectConfigured establishes an SSH tunnel using the configured default endpoint.
func (a *App) ConnectConfigured(ctx context.Context, hostKeyApproval sshtunnel.HostKeyApprovalHandler, onDisconnect func()) (*ConnectResult, error) {
	registry := a.Config.ClientEndpointsOrDefault()
	alias, endpoint, ok := registry.DefaultEndpoint()
	if !ok {
		return nil, fmt.Errorf("no default signer endpoint in endpoints.yaml")
	}
	return a.connectEndpoint(ctx, alias, endpoint, hostKeyApproval, onDisconnect)
}

// ConnectEndpointAlias establishes an SSH tunnel to a configured endpoint alias.
func (a *App) ConnectEndpointAlias(ctx context.Context, alias string, hostKeyApproval sshtunnel.HostKeyApprovalHandler, onDisconnect func()) (*ConnectResult, error) {
	endpoint, err := a.configuredEndpoint(alias)
	if err != nil {
		return nil, err
	}
	return a.connectEndpoint(ctx, alias, endpoint, hostKeyApproval, onDisconnect)
}

func (a *App) configuredEndpoint(alias string) (config.ClientEndpointConfig, error) {
	endpoint, ok := a.Config.ClientEndpointsOrDefault().Endpoint(alias)
	if !ok {
		return config.ClientEndpointConfig{}, fmt.Errorf("unknown endpoint alias %q", alias)
	}
	return endpoint, nil
}

func (a *App) connectEndpoint(ctx context.Context, alias string, endpoint config.ClientEndpointConfig, hostKeyApproval sshtunnel.HostKeyApprovalHandler, onDisconnect func()) (*ConnectResult, error) {
	endpointSSH, err := config.ResolveClientEndpointSSH(endpoint)
	if err != nil {
		return nil, err
	}
	return a.Connect(ctx, ConnectRequest{
		Host:            endpointSSH.Host,
		SSHPort:         endpointSSH.Port,
		IdentityFile:    endpointSSH.IdentityFile,
		KnownHostsPath:  endpointSSH.KnownHostsPath,
		TokenFile:       endpointSSH.TokenFile,
		EndpointName:    alias,
		HostKeyApproval: hostKeyApproval,
		OnDisconnect:    onDisconnect,
	})
}

// Disconnect closes an active tunnel connection.
func (a *App) Disconnect(_ context.Context) (*DisconnectResult, error) {
	wasConnected := a.eng.IsTunnelConnected()
	if !wasConnected {
		return &DisconnectResult{WasConnected: false}, nil
	}
	if err := a.eng.Disconnect(); err != nil {
		return nil, err
	}
	return &DisconnectResult{
		WasConnected: true,
		Summary:      Summary{Message: "Tunnel disconnected"},
	}, nil
}

// TokenRequestTarget is the endpoint a request-token run enrolls with.
type TokenRequestTarget struct {
	Alias string
	// AutoConnect reports that the target is the default signer endpoint, so
	// the shell replaces its current session with one using the new token.
	AutoConnect bool
}

// ResolveTokenRequestTarget resolves a request-token alias; an empty alias
// selects the default signer endpoint.
func (a *App) ResolveTokenRequestTarget(alias string) (TokenRequestTarget, error) {
	registry := a.Config.ClientEndpointsOrDefault()
	defaultAlias, defaultEndpoint, hasDefault := registry.DefaultEndpoint()
	if alias == "" {
		if !hasDefault {
			return TokenRequestTarget{}, fmt.Errorf("no default signer endpoint in endpoints.yaml; import or configure a signer endpoint before running request-token")
		}
		alias = defaultAlias
	}
	if _, err := a.configuredEndpoint(alias); err != nil {
		return TokenRequestTarget{}, err
	}
	return TokenRequestTarget{
		Alias:       alias,
		AutoConnect: hasDefault && alias == defaultAlias && defaultEndpoint.Role == config.ClientEndpointRoleSigner,
	}, nil
}

// RequestTokenEndpointAlias enrolls with a configured endpoint alias and saves
// the issued token. progress, when set, receives the client key fingerprint
// once the request is waiting for operator approval.
func (a *App) RequestTokenEndpointAlias(ctx context.Context, alias string, hostKeyApproval sshtunnel.HostKeyApprovalHandler, progress func(string)) (*RequestTokenResult, error) {
	endpoint, err := a.configuredEndpoint(alias)
	if err != nil {
		return nil, err
	}
	wasConnected := a.eng.IsTunnelConnected()
	result, err := clientenroll.RequestEndpointToken(
		ctx,
		currentDestinationTokenClient{TokenClient: a.eng, app: a, alias: alias, requested: endpoint},
		a.DataDir,
		alias,
		endpoint,
		hostKeyApproval,
		progress,
	)
	if err != nil {
		return nil, err
	}

	requestResult := &RequestTokenResult{
		TokenPath:        result.TokenPath,
		DisconnectedPrev: wasConnected,
		Summary:          Summary{Message: fmt.Sprintf("Token received and saved to %s", result.TokenPath)},
	}
	requestResult.RenderLines = []string{fmt.Sprintf("✓ %s", requestResult.Summary.Message)}
	return requestResult, nil
}

// currentDestinationTokenClient requests a token through the engine and saves
// it only while the alias still names the destination that issued it.
type currentDestinationTokenClient struct {
	clientenroll.TokenClient
	app       *App
	alias     string
	requested config.ClientEndpointConfig
}

func (c currentDestinationTokenClient) SaveApshellTokenToPath(_, token string) (string, error) {
	return c.app.saveEndpointTokenIfCurrent(c.alias, c.requested, token)
}

func (a *App) tokenPathForRequest(tokenPath string) (string, error) {
	if tokenPath != "" {
		return tokenPath, nil
	}
	return tokenfile.GetApshellTokenPathForDataDir(a.DataDir)
}

func decorateConnectResult(res *ConnectResult) {
	if res == nil {
		return
	}
	if res.AlreadyConnected {
		res.RenderLines = []string{res.Summary.Message}
		return
	}
	res.RenderLines = append(res.RenderLines,
		"✓ SSH tunnel established via public key",
		fmt.Sprintf("✓ %s", res.Summary.Message),
	)
	if !res.Locked && res.KeyCount > 0 {
		res.RenderLines = append(res.RenderLines, fmt.Sprintf("✓ Loaded %d signing key(s)", res.KeyCount))
	}
}

var _ = engine.ErrAlreadyConnected
