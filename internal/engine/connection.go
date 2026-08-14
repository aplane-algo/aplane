// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

// ConnectWithTunnel establishes an SSH tunnel connection using 2FA: API token + public key.
// This method handles the tunnel setup and returns the result.
// hostKeyApproval is called for TOFU when connecting to an unknown server (can be nil to reject unknown hosts).
func (e *Core) ConnectWithTunnel(target string, host string, sshPort int, localPort int, signerPort int, token string, identityFile string, knownHostsPath string, hostKeyApproval sshtunnel.HostKeyApprovalHandler, onDisconnect func()) (*ConnectionResult, error) {
	result, err := e.Connection.ConnectWithTunnel(
		target, host, sshPort, localPort, signerPort, token, identityFile, knownHostsPath, hostKeyApproval,
		e.populateSignerCache,
		e.handleConnectionClosed(onDisconnect),
	)
	if err != nil {
		if errors.Is(err, connect.ErrAlreadyConnected) {
			return nil, fmt.Errorf("%w: %s", ErrAlreadyConnected, e.GetConnectionTarget())
		}
		if result == nil {
			result = &connect.Result{Target: target}
		}
		return &ConnectionResult{
			Connected:    result.Connected,
			Target:       target,
			Port:         result.Port,
			KeyCount:     result.KeyCount,
			Locked:       result.Locked,
			ErrorMessage: result.ErrorMessage,
		}, err
	}
	return &ConnectionResult{
		Connected: result.Connected,
		Target:    result.Target,
		Port:      result.Port,
		KeyCount:  result.KeyCount,
		Locked:    result.Locked,
	}, nil
}

// Disconnect closes the connection to Signer
func (e *Core) Disconnect() error {
	return e.Connection.Disconnect(e.handleConnectionClosed(nil))
}

// IsConnected returns the current connection status
func (e *Core) IsConnected() bool {
	return e.Connection.IsConnected()
}

// IsTunnelConnected returns whether connected via SSH tunnel
func (e *Core) IsTunnelConnected() bool {
	return e.Connection.IsTunnelConnected()
}

// GetConnectionTarget returns the current connection target
func (e *Core) GetConnectionTarget() string {
	return e.Connection.GetConnectionTarget()
}

// RequestTokenWithContext connects to the SSH server and requests a token provisioning.
func (e *Core) RequestTokenWithContext(ctx context.Context, host string, sshPort int, identityFile string, knownHostsPath string, hostKeyApproval sshtunnel.HostKeyApprovalHandler, onProvisioningStart func()) (string, error) {
	// Disconnect if currently connected (old token will be invalid after provisioning)
	if e.IsTunnelConnected() {
		_ = e.Disconnect()
	}
	return e.Connection.RequestTokenWithContext(ctx, host, sshPort, identityFile, knownHostsPath, hostKeyApproval, onProvisioningStart)
}

func (e *Core) GetKeysWithContext(ctx context.Context) (*signerapi.KeysResult, error) {
	return e.Connection.GetKeysWithContext(ctx)
}

func (e *Core) GetKeyTypesWithContext(ctx context.Context) (*signerapi.KeyTypesResponse, error) {
	return e.Connection.GetKeyTypesWithContext(ctx)
}

func (e *Core) GetSignerStatusWithContext(ctx context.Context) (*signerapi.StatusResponse, error) {
	return e.Connection.GetSignerStatusWithContext(ctx)
}

func (e *Core) AdminGenerateWithContext(ctx context.Context, keyType string, params map[string]string) (*signerapi.AdminGenerateResponse, error) {
	return e.Connection.AdminGenerateWithContext(ctx, keyType, params)
}

func (e *Core) AdminDeleteKeyWithContext(ctx context.Context, address string) (*signerapi.AdminDeleteResponse, error) {
	return e.Connection.AdminDeleteKeyWithContext(ctx, address)
}

func (e *Core) AdminSyncSentryReferencesWithContext(ctx context.Context, candidates []signerapi.SentryReferenceCandidate) (*signerapi.AdminSyncSentryReferencesResponse, error) {
	return e.Connection.AdminSyncSentryReferencesWithContext(ctx, candidates)
}

func (e *Core) RequestGroupPlanWithContext(ctx context.Context, requests []signerapi.SignRequest) (*signerapi.GroupPlanResponse, error) {
	if err := e.validateAlgodConsensus(ctx); err != nil {
		return nil, fmt.Errorf("validate algod consensus before group planning: %w", err)
	}
	return e.Connection.RequestGroupPlanWithContext(ctx, requests)
}

func (e *Core) RequestGroupSignWithContext(ctx context.Context, requests []signerapi.SignRequest) (*signerapi.GroupSignResponse, error) {
	return e.Connection.RequestGroupSignWithContext(ctx, requests)
}

func (e *Core) handleConnectionClosed(onDisconnect func()) func() {
	return func() {
		e.resetSignerStatusRevision()
		e.resetSignerCache(false)
		if onDisconnect != nil {
			onDisconnect()
		}
	}
}
