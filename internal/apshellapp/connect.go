// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/aplane-algo/aplane/internal/clientenroll"
	"github.com/aplane-algo/aplane/internal/config"
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
	HostKeyApproval sshtunnel.HostKeyApprovalHandler
	OnDisconnect    func()
}

// Connect establishes an SSH connection authenticated by the client's
// enrolled key. Requests to the signer travel over it in-process; nothing
// listens on this machine.
func (a *App) Connect(ctx context.Context, req ConnectRequest) (*ConnectResult, error) {
	target := fmt.Sprintf("%s (ssh:%d)", req.Host, req.SSHPort)
	connectResult, err := a.eng.ConnectWithTunnel(
		ctx,
		target,
		req.Host,
		req.SSHPort,
		req.IdentityFile,
		req.KnownHostsPath,
		req.HostKeyApproval,
		req.OnDisconnect,
	)
	if err != nil {
		if isAuthenticationFailure(err) {
			return nil, fmt.Errorf("authentication failed: this client's SSH key (%s) is not enrolled at the signer, or was revoked.\nRun 'enroll' and have the operator approve it", req.IdentityFile)
		}
		return nil, err
	}
	res := &ConnectResult{
		Target:   target,
		KeyCount: connectResult.KeyCount,
		Locked:   connectResult.Locked,
	}

	if connectResult.AlreadyConnected {
		res.AlreadyConnected = true
		res.Summary = Summary{Message: fmt.Sprintf("Already connected to %s", target)}
		decorateConnectResult(res)
		return res, nil
	}

	res.Summary = Summary{Message: fmt.Sprintf("Signer verified over SSH at %s", target)}
	if connectResult.Locked {
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
	_, endpoint, ok := registry.SignerEndpoint()
	if !ok {
		return nil, fmt.Errorf("no default signer endpoint in endpoints.yaml")
	}
	return a.connectEndpoint(ctx, endpoint, hostKeyApproval, onDisconnect)
}

// ConnectEndpointAlias establishes an SSH tunnel to a configured endpoint alias.
func (a *App) ConnectEndpointAlias(ctx context.Context, alias string, hostKeyApproval sshtunnel.HostKeyApprovalHandler, onDisconnect func()) (*ConnectResult, error) {
	endpoint, err := a.configuredEndpoint(alias)
	if err != nil {
		return nil, err
	}
	return a.connectEndpoint(ctx, endpoint, hostKeyApproval, onDisconnect)
}

// SetIdentityCreatedHandler sets what happens when connecting generates a new SSH
// identity key. The shell announces it as progress.
func (a *App) SetIdentityCreatedHandler(handler func(sshtunnel.IdentityCreated)) {
	a.eng.Connection.SetIdentityCreatedHandler(handler)
}

// SetProgressOutput routes live signer progress lines (such as approval wait
// notices) to w instead of discarding them.
func (a *App) SetProgressOutput(w io.Writer) {
	a.eng.Connection.SetProgressOutput(w)
}

func (a *App) configuredEndpoint(alias string) (config.ClientEndpointConfig, error) {
	endpoint, ok := a.Config.ClientEndpointsOrDefault().Endpoint(alias)
	if !ok {
		return config.ClientEndpointConfig{}, fmt.Errorf("unknown endpoint alias %q", alias)
	}
	return endpoint, nil
}

func (a *App) connectEndpoint(ctx context.Context, endpoint config.ClientEndpointConfig, hostKeyApproval sshtunnel.HostKeyApprovalHandler, onDisconnect func()) (*ConnectResult, error) {
	endpointSSH, err := config.ResolveClientEndpointSSH(endpoint)
	if err != nil {
		return nil, err
	}
	return a.Connect(ctx, ConnectRequest{
		Host:            endpointSSH.Host,
		SSHPort:         endpointSSH.Port,
		IdentityFile:    endpointSSH.IdentityFile,
		KnownHostsPath:  endpointSSH.KnownHostsPath,
		HostKeyApproval: hostKeyApproval,
		OnDisconnect:    onDisconnect,
	})
}

// Disconnect closes an active tunnel connection.
func (a *App) Disconnect(_ context.Context) (*DisconnectResult, error) {
	wasConnected := a.eng.IsConnected()
	if !wasConnected {
		return &DisconnectResult{WasConnected: false}, nil
	}
	a.eng.Disconnect()
	return &DisconnectResult{
		WasConnected: true,
		Summary:      Summary{Message: "Tunnel disconnected"},
	}, nil
}

// EnrollmentTarget is the endpoint an enroll run enrolls with.
type EnrollmentTarget struct {
	Alias string
	// AutoConnect reports that the target is the default signer endpoint, so
	// the shell replaces its current session with one using the enrolled key.
	AutoConnect bool
}

// ResolveEnrollmentTarget resolves an enroll alias; an empty alias
// selects the default signer endpoint.
func (a *App) ResolveEnrollmentTarget(alias string) (EnrollmentTarget, error) {
	registry := a.Config.ClientEndpointsOrDefault()
	signerAlias, _, hasSigner := registry.SignerEndpoint()
	if alias == "" {
		if !hasSigner {
			return EnrollmentTarget{}, fmt.Errorf("no default signer endpoint in endpoints.yaml; import or configure a signer endpoint before running enroll")
		}
		alias = signerAlias
	}
	if _, err := a.configuredEndpoint(alias); err != nil {
		return EnrollmentTarget{}, err
	}
	return EnrollmentTarget{
		Alias:       alias,
		AutoConnect: hasSigner && alias == signerAlias,
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
