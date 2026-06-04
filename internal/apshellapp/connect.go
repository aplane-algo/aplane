// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

// ConnectRequest establishes an SSH tunnel to the signer.
type ConnectRequest struct {
	Host            string
	SSHPort         int
	SignerPort      int
	IdentityFile    string
	KnownHostsPath  string
	TokenFile       string
	EndpointName    string
	HostKeyApproval sshtunnel.HostKeyApprovalHandler
	OnDisconnect    func()
}

// RequestTokenRequest requests a fresh apshell API token from the signer host.
type RequestTokenRequest struct {
	Host                  string
	SSHPort               int
	IdentityFile          string
	KnownHostsPath        string
	TokenFile             string
	EndpointName          string
	HostKeyApproval       sshtunnel.HostKeyApprovalHandler
	OnProvisioningStarted func()
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

	localPort, err := findAvailablePort()
	if err != nil {
		return nil, fmt.Errorf("failed to find available local port: %w", err)
	}

	target := fmt.Sprintf("%s (ssh:%d, signer:%d)", req.Host, req.SSHPort, req.SignerPort)
	connectResult, err := a.eng.ConnectWithTunnel(
		target,
		req.Host,
		req.SSHPort,
		localPort,
		req.SignerPort,
		token,
		req.IdentityFile,
		req.KnownHostsPath,
		req.HostKeyApproval,
		req.OnDisconnect,
	)
	if err != nil {
		if strings.Contains(err.Error(), "401") ||
			strings.Contains(err.Error(), "Invalid token") ||
			strings.Contains(err.Error(), "unable to authenticate") {
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

// ConnectConfigured establishes an SSH tunnel using the configured ssh block.
func (a *App) ConnectConfigured(ctx context.Context, hostKeyApproval sshtunnel.HostKeyApprovalHandler, onDisconnect func()) (*ConnectResult, error) {
	registry := a.Config.ClientEndpointsOrDefault(a.DataDir)
	alias, endpoint, ok := registry.DefaultEndpoint()
	if !ok {
		return nil, fmt.Errorf("no ssh block in config.yaml — add ssh host, port, and identity_file")
	}
	return a.ConnectEndpoint(ctx, alias, endpoint, hostKeyApproval, onDisconnect)
}

func (a *App) ConnectEndpoint(ctx context.Context, alias string, endpoint config.ClientEndpointConfig, hostKeyApproval sshtunnel.HostKeyApprovalHandler, onDisconnect func()) (*ConnectResult, error) {
	host, sshPort, err := sshEndpointHostPort(endpoint)
	if err != nil {
		return nil, err
	}
	signerPort := endpoint.SignerPort
	if signerPort == 0 {
		signerPort = a.Config.SignerPort
	}
	return a.Connect(ctx, ConnectRequest{
		Host:            host,
		SSHPort:         sshPort,
		SignerPort:      signerPort,
		IdentityFile:    endpoint.IdentityFile,
		KnownHostsPath:  endpoint.KnownHostsPath,
		TokenFile:       endpoint.TokenFile,
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

// RequestToken requests and persists a fresh apshell token for the configured client data dir.
func (a *App) RequestToken(_ context.Context, req RequestTokenRequest) (*RequestTokenResult, error) {
	wasConnected := a.eng.IsTunnelConnected()
	token, err := a.eng.RequestToken(req.Host, req.SSHPort, req.IdentityFile, req.KnownHostsPath, req.HostKeyApproval, req.OnProvisioningStarted)
	if err != nil {
		return nil, err
	}

	tokenPath, err := a.tokenPathForRequest(req.TokenFile)
	if err != nil {
		return nil, err
	}
	tokenPath, err = a.eng.SaveApshellTokenToPath(tokenPath, token)
	if err != nil {
		return nil, fmt.Errorf("failed to save token: %w", err)
	}

	result := &RequestTokenResult{
		TokenPath:        tokenPath,
		DisconnectedPrev: wasConnected,
		Summary:          Summary{Message: fmt.Sprintf("Token received and saved to %s", tokenPath)},
	}
	result.RenderLines = []string{
		fmt.Sprintf("✓ %s", result.Summary.Message),
	}
	return result, nil
}

// RequestTokenConfigured requests and persists a fresh apshell token using the configured ssh block.
func (a *App) RequestTokenConfigured(ctx context.Context, hostKeyApproval sshtunnel.HostKeyApprovalHandler) (*RequestTokenResult, error) {
	registry := a.Config.ClientEndpointsOrDefault(a.DataDir)
	alias, endpoint, ok := registry.DefaultEndpoint()
	if !ok {
		return nil, fmt.Errorf("usage: request-token [<host> [--ssh-port <port>]]\n\n" +
			"Request an API token from the Signer. Requires an operator\n" +
			"(apadmin) to approve the request on the server.\n" +
			"If no arguments are given, apshell uses the ssh block from config.yaml.\n\n" +
			"Examples:\n" +
			"  request-token\n" +
			"  request-token 192.168.1.100\n" +
			"  request-token 192.168.1.100 --ssh-port 2222")
	}
	return a.RequestTokenEndpoint(ctx, alias, endpoint, hostKeyApproval)
}

func (a *App) RequestTokenEndpoint(ctx context.Context, alias string, endpoint config.ClientEndpointConfig, hostKeyApproval sshtunnel.HostKeyApprovalHandler, onProvisioningStarted ...func()) (*RequestTokenResult, error) {
	host, sshPort, err := sshEndpointHostPort(endpoint)
	if err != nil {
		return nil, err
	}
	var progress func()
	if len(onProvisioningStarted) > 0 {
		progress = onProvisioningStarted[0]
	}
	return a.RequestToken(ctx, RequestTokenRequest{
		Host:                  host,
		SSHPort:               sshPort,
		IdentityFile:          endpoint.IdentityFile,
		KnownHostsPath:        endpoint.KnownHostsPath,
		TokenFile:             endpoint.TokenFile,
		EndpointName:          alias,
		HostKeyApproval:       hostKeyApproval,
		OnProvisioningStarted: progress,
	})
}

func (a *App) tokenPathForRequest(tokenPath string) (string, error) {
	if tokenPath != "" {
		return tokenPath, nil
	}
	return tokenfile.GetApshellTokenPathForDataDir(a.DataDir)
}

func sshEndpointHostPort(endpoint config.ClientEndpointConfig) (string, int, error) {
	parsed, err := url.Parse(endpoint.URL)
	if err != nil {
		return "", 0, fmt.Errorf("invalid endpoint URL: %w", err)
	}
	if parsed.Scheme != "ssh" {
		return "", 0, fmt.Errorf("endpoint %q cannot be used for primary signer connection; connect requires ssh://", endpoint.URL)
	}
	host := parsed.Hostname()
	if host == "" {
		return "", 0, fmt.Errorf("endpoint %q has no SSH host", endpoint.URL)
	}
	sshPort := config.DefaultSSHPort
	if parsed.Port() != "" {
		port, err := strconv.Atoi(parsed.Port())
		if err != nil || port <= 0 || port > 65535 {
			return "", 0, fmt.Errorf("invalid SSH port %q", parsed.Port())
		}
		sshPort = port
	}
	return host, sshPort, nil
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

func findAvailablePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = listener.Close() }()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

var _ = engine.ErrAlreadyConnected
