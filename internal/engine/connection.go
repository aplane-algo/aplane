// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package engine

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"github.com/aplane-algo/aplane/internal/util"
)

// populateSignerCache populates the signer cache with key info from the /keys response.
// This extracts key types, bytecode sizes (for budget calculation), and generic LSig markers.
func (e *Engine) populateSignerCache(keys []util.KeyInfo) {
	e.SignerCache = util.NewSignerCache()
	for _, keyInfo := range keys {
		e.SignerCache.Keys[keyInfo.Address] = keyInfo.KeyType

		// Populate total LSig size for budget calculation
		if keyInfo.LsigSize > 0 {
			e.SignerCache.SetLsigSize(keyInfo.Address, keyInfo.LsigSize)
		}

		// Mark generic LSigs (no crypto signature needed)
		if keyInfo.IsGenericLsig {
			e.SignerCache.SetGenericLsig(keyInfo.Address, true)
		}
	}
	e.SignerCache.SetColorFormatter(algorithm.GetDisplayColor)
}

// ConnectDirect connects directly to Signer (for localhost, no SSH tunnel)
func (e *Engine) ConnectDirect(hostPort string, token string) (*ConnectionResult, error) {
	e.connMu.Lock()
	defer e.connMu.Unlock()

	// Check if already connected
	if e.SignerClient != nil {
		if e.connectionTarget == hostPort {
			return &ConnectionResult{
				Connected: true,
				Target:    hostPort,
			}, nil
		}
		return nil, fmt.Errorf("%w: already connected to %s", ErrAlreadyConnected, e.connectionTarget)
	}

	result := &ConnectionResult{Target: hostPort}

	baseURL := fmt.Sprintf("http://%s", hostPort)

	// Create client with token
	signerClient := util.NewSignerClientWithToken(baseURL, token)

	// Verify connection and token by fetching keys (requires auth)
	keysResp, err := signerClient.GetKeys("")
	if err != nil {
		result.ErrorMessage = err.Error()
		return result, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	// Connection and auth verified, set up state
	e.SignerClient = signerClient
	e.connectionTarget = hostPort

	// Set up signer cache from the keys we already fetched
	e.populateSignerCache(keysResp.Keys)

	result.Connected = true
	result.KeyCount = keysResp.Count

	return result, nil
}

// ConnectWithTunnel establishes an SSH tunnel connection using 2FA: API token + public key.
// This method handles the tunnel setup and returns the result.
// hostKeyApproval is called for TOFU when connecting to an unknown server (can be nil to reject unknown hosts).
func (e *Engine) ConnectWithTunnel(target string, host string, sshPort int, localPort int, signerPort int, token string, identityFile string, knownHostsPath string, hostKeyApproval sshtunnel.HostKeyApprovalHandler) (*ConnectionResult, error) {
	e.connMu.Lock()

	// Check if already connected
	if e.SignerClient != nil {
		if e.connectionTarget == target {
			e.connMu.Unlock()
			return &ConnectionResult{
				Connected: true,
				Target:    target,
			}, nil
		}
		e.connMu.Unlock()
		return nil, fmt.Errorf("%w: already connected to %s", ErrAlreadyConnected, e.connectionTarget)
	}
	e.connMu.Unlock()

	result := &ConnectionResult{Target: target}

	if token == "" {
		result.ErrorMessage = "no API token configured"
		return result, fmt.Errorf("no API token configured")
	}

	// Check if local port is already in use
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", localPort), 100*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return result, fmt.Errorf("port %d is already in use locally", localPort)
	}

	// Create SSH tunnel client
	client := sshtunnel.NewClient(host, sshPort, localPort, signerPort, identityFile, knownHostsPath)
	client.SetAPIToken(token)

	// Set up TOFU host key approval handler if provided
	if hostKeyApproval != nil {
		client.SetHostKeyApprovalHandler(hostKeyApproval)
	}

	// Set up disconnect callback
	client.SetDisconnectCallback(func() {
		e.connMu.Lock()
		if e.sshTunnelClient != nil {
			_ = e.sshTunnelClient.Close()
		}
		e.clearConnectionStateLocked()
		e.connMu.Unlock()
	})

	// Create context for connection
	ctx := context.Background()

	if err := client.ConnectWithKey(ctx); err != nil {
		result.ErrorMessage = err.Error()
		return result, fmt.Errorf("SSH auth failed: %w", err)
	}

	// Start port forwarding
	if err := client.StartPortForwarding(ctx); err != nil {
		_ = client.Close()
		result.ErrorMessage = err.Error()
		return result, fmt.Errorf("failed to start port forwarding: %w", err)
	}

	// Wait a moment for tunnel to establish
	time.Sleep(1 * time.Second)

	// Create Signer client and verify connection
	signerClient := util.NewSignerClientWithToken(fmt.Sprintf("http://localhost:%d", localPort), token)

	// Verify connection and token by fetching keys (requires auth)
	keysResp, err := signerClient.GetKeys("")
	if err != nil {
		_ = client.Close()
		result.ErrorMessage = err.Error()
		return result, fmt.Errorf("failed to verify connection: %w", err)
	}

	// Connection and auth verified, set up state
	e.connMu.Lock()
	e.SignerClient = signerClient
	e.connectionTarget = target
	e.sshTunnelClient = client
	e.tunnelConnected = true
	e.tunnelCtx, e.tunnelCancel = context.WithCancel(context.Background())
	e.connMu.Unlock()

	// Set up signer cache from the keys we already fetched
	e.populateSignerCache(keysResp.Keys)

	result.Connected = true
	result.Port = localPort
	result.KeyCount = keysResp.Count

	return result, nil
}

// Disconnect closes the connection to Signer
func (e *Engine) Disconnect() error {
	e.connMu.Lock()
	defer e.connMu.Unlock()

	if e.SignerClient == nil {
		return nil // Already disconnected
	}

	// Cancel context to signal clean shutdown
	if e.tunnelCancel != nil {
		e.tunnelCancel()
	}

	// Close the SSH tunnel client if present
	if e.sshTunnelClient != nil {
		_ = e.sshTunnelClient.Close()
	}

	e.clearConnectionStateLocked()
	return nil
}

// clearConnectionStateLocked clears all connection-related state
// Must be called with connMu held
func (e *Engine) clearConnectionStateLocked() {
	e.sshTunnelClient = nil
	e.tunnelConnected = false
	e.SignerClient = nil
	e.connectionTarget = ""
	e.tunnelCtx = nil
	e.tunnelCancel = nil
	e.SignerCache = util.NewSignerCache()
	e.SignerCache.SetColorFormatter(algorithm.GetDisplayColor)
}

// IsConnected returns the current connection status
func (e *Engine) IsConnected() bool {
	e.connMu.Lock()
	defer e.connMu.Unlock()
	return e.SignerClient != nil
}

// IsTunnelConnected returns whether connected via SSH tunnel
func (e *Engine) IsTunnelConnected() bool {
	e.connMu.Lock()
	defer e.connMu.Unlock()
	return e.tunnelConnected
}

// GetConnectionTarget returns the current connection target
func (e *Engine) GetConnectionTarget() string {
	e.connMu.Lock()
	defer e.connMu.Unlock()
	return e.connectionTarget
}

// SetConnectionTarget sets the connection target
func (e *Engine) SetConnectionTarget(target string) {
	e.connMu.Lock()
	defer e.connMu.Unlock()
	e.connectionTarget = target
}

// GetSSHPort returns the current SSH port
func (e *Engine) GetSSHPort() int {
	e.connMu.Lock()
	defer e.connMu.Unlock()
	return e.sshPort
}

// SetSSHPort sets the SSH port
func (e *Engine) SetSSHPort(port int) {
	e.connMu.Lock()
	defer e.connMu.Unlock()
	e.sshPort = port
}

// SetTunnelConnected sets the tunnel connected state
func (e *Engine) SetTunnelConnected(connected bool) {
	e.connMu.Lock()
	defer e.connMu.Unlock()
	e.tunnelConnected = connected
}

// GetSSHTunnelClient returns the SSH tunnel client
func (e *Engine) GetSSHTunnelClient() *sshtunnel.Client {
	e.connMu.Lock()
	defer e.connMu.Unlock()
	return e.sshTunnelClient
}

// SetSSHTunnelClient sets the SSH tunnel client
func (e *Engine) SetSSHTunnelClient(client *sshtunnel.Client) {
	e.connMu.Lock()
	defer e.connMu.Unlock()
	e.sshTunnelClient = client
}

// GetTunnelContext returns the tunnel context and cancel function
func (e *Engine) GetTunnelContext() (context.Context, context.CancelFunc) {
	e.connMu.Lock()
	defer e.connMu.Unlock()
	return e.tunnelCtx, e.tunnelCancel
}

// SetTunnelContext sets the tunnel context and cancel function
func (e *Engine) SetTunnelContext(ctx context.Context, cancel context.CancelFunc) {
	e.connMu.Lock()
	defer e.connMu.Unlock()
	e.tunnelCtx = ctx
	e.tunnelCancel = cancel
}

// CheckLocalhostConnection does a quick port check for localhost connections
// Returns true if connected, false if disconnected
func (e *Engine) CheckLocalhostConnection() bool {
	e.connMu.Lock()
	client := e.SignerClient
	isTunnel := e.tunnelConnected
	target := e.connectionTarget
	e.connMu.Unlock()

	// No client or using SSH tunnel (which has its own detection)
	if client == nil || isTunnel {
		return client != nil
	}

	// Quick TCP check for localhost connection
	conn, err := net.DialTimeout("tcp", target, 100*time.Millisecond)
	if err != nil {
		// Server is down - clear connection state
		e.connMu.Lock()
		e.clearConnectionStateLocked()
		e.connMu.Unlock()
		return false
	}
	_ = conn.Close()
	return true
}

// GetSignerClient returns the Signer client (for signing operations)
func (e *Engine) GetSignerClient() *util.SignerClient {
	e.connMu.Lock()
	defer e.connMu.Unlock()
	return e.SignerClient
}
