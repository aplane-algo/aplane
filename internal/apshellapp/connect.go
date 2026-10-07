// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/aplane-algo/aplane/internal/clientenroll"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	engineconnect "github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

// isAuthenticationFailure reports whether a connect error is an
// authentication problem: the node refused this client's key at the SSH
// handshake (typed as ErrSSHKeyNotEnrolled), or the signer answered 401.
func isAuthenticationFailure(err error) bool {
	if errors.Is(err, engineconnect.ErrSSHKeyNotEnrolled) {
		return true
	}
	var herr *signerclient.HTTPStatusError
	if errors.As(err, &herr) {
		return herr.StatusCode == http.StatusUnauthorized
	}
	return false
}

// ConnectRequest establishes an SSH tunnel to the signer.
type ConnectRequest struct {
	Host            string
	SSHPort         int
	IdentityFile    string
	KnownHostsPath  string
	EndpointName    string
	HostKeyApproval sshtunnel.HostKeyApprovalHandler
	OnDisconnect    func()
}

// Connect establishes an SSH tunnel authenticated by the client's enrolled key.
func (a *App) Connect(_ context.Context, req ConnectRequest) (*ConnectResult, error) {
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
		req.IdentityFile,
		req.KnownHostsPath,
		req.HostKeyApproval,
		req.OnDisconnect,
	)
	if err != nil {
		if isAuthenticationFailure(err) {
			return nil, fmt.Errorf("authentication failed: this client's SSH key (%s) is not enrolled at the signer, or was revoked.\nRun 'request-enrollment' and have the operator approve it", req.IdentityFile)
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

// EnrollmentTarget is the endpoint a request-enrollment run enrolls with.
type EnrollmentTarget struct {
	Alias string
	// AutoConnect reports that the target is the default signer endpoint, so
	// the shell replaces its current session with one using the enrolled key.
	AutoConnect bool
}

// ResolveEnrollmentTarget resolves a request-enrollment alias; an empty alias
// selects the default signer endpoint.
func (a *App) ResolveEnrollmentTarget(alias string) (EnrollmentTarget, error) {
	registry := a.Config.ClientEndpointsOrDefault()
	defaultAlias, defaultEndpoint, hasDefault := registry.DefaultEndpoint()
	if alias == "" {
		if !hasDefault {
			return EnrollmentTarget{}, fmt.Errorf("no default signer endpoint in endpoints.yaml; import or configure a signer endpoint before running request-enrollment")
		}
		alias = defaultAlias
	}
	if _, err := a.configuredEndpoint(alias); err != nil {
		return EnrollmentTarget{}, err
	}
	return EnrollmentTarget{
		Alias:       alias,
		AutoConnect: hasDefault && alias == defaultAlias && defaultEndpoint.Role == config.ClientEndpointRoleSigner,
	}, nil
}

// RequestEnrollmentEndpointAlias asks a configured endpoint to enroll this
// client's SSH key under an optional display label and returns at once: the
// request waits for the node's operator, and the client connects once it is
// approved. progress, when set, receives the client key fingerprint as the
// request is submitted. Nothing is stored on the client: the key is the
// credential.
func (a *App) RequestEnrollmentEndpointAlias(ctx context.Context, alias, label string, hostKeyApproval sshtunnel.HostKeyApprovalHandler, progress func(string)) (*RequestEnrollmentResult, error) {
	endpoint, err := a.configuredEndpoint(alias)
	if err != nil {
		return nil, err
	}
	result, err := clientenroll.RequestEndpointEnrollment(ctx, a.eng, alias, endpoint, label, hostKeyApproval, progress)
	if err != nil {
		return nil, err
	}

	requestResult := &RequestEnrollmentResult{
		Alias:       result.Alias,
		Fingerprint: result.Fingerprint,
		Pending:     result.Pending,
	}
	if result.Pending {
		requestResult.Summary = Summary{Message: fmt.Sprintf("Enrollment request for client key %s is waiting for the operator at endpoint %s", result.Fingerprint, result.Alias)}
		requestResult.RenderLines = []string{
			fmt.Sprintf("✓ %s", requestResult.Summary.Message),
			"The operator approves it in apadmin (Enrolled Clients). Run 'connect' once it is approved.",
		}
		return requestResult, nil
	}
	requestResult.Summary = Summary{Message: fmt.Sprintf("Client key %s is already enrolled at endpoint %s", result.Fingerprint, result.Alias)}
	requestResult.RenderLines = []string{fmt.Sprintf("✓ %s", requestResult.Summary.Message)}
	return requestResult, nil
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
