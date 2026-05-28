// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package connect

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

// Result reports the outcome of a remote signer connection attempt.
type Result struct {
	Connected    bool
	Target       string
	Port         int
	KeyCount     int
	Locked       bool
	ErrorMessage string
}

// ConnectWithTunnel establishes an SSH tunnel connection and verifies the signer token.
func (s *ConnectionState) ConnectWithTunnel(
	target string,
	host string,
	sshPort int,
	localPort int,
	signerPort int,
	token string,
	identityFile string,
	knownHostsPath string,
	hostKeyApproval sshtunnel.HostKeyApprovalHandler,
	onKeys func([]signerapi.KeyInfo),
	onDisconnect func(),
) (*Result, error) {
	alreadyConnected, currentTarget, inProgress := s.beginConnect(target)
	if alreadyConnected {
		return &Result{Connected: true, Target: target}, nil
	}
	if inProgress {
		if currentTarget == target {
			return nil, fmt.Errorf("connection to %s already in progress", target)
		}
		return nil, fmt.Errorf("already connecting to %s", currentTarget)
	}
	if currentTarget != "" {
		return nil, fmt.Errorf("already connected to %s", currentTarget)
	}

	result := &Result{Target: target}
	defer func() {
		if !result.Connected {
			s.clearPendingConnect(target)
		}
	}()
	if token == "" {
		result.ErrorMessage = "no API token configured"
		return result, fmt.Errorf("no API token configured")
	}

	dialTimeout := s.portDialTimeout
	if dialTimeout == nil {
		dialTimeout = net.DialTimeout
	}
	conn, err := dialTimeout("tcp", fmt.Sprintf("localhost:%d", localPort), 100*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return result, fmt.Errorf("port %d is already in use locally", localPort)
	}

	client := sshtunnel.NewClient(host, sshPort, localPort, signerPort, identityFile, knownHostsPath)
	client.SetAPIToken(token)
	if hostKeyApproval != nil {
		client.SetHostKeyApprovalHandler(hostKeyApproval)
	}

	client.SetDisconnectCallback(func() {
		s.Mu.Lock()
		if s.SSHTunnelClient == client {
			_ = s.SSHTunnelClient.Close()
			s.clearLocked()
		}
		s.Mu.Unlock()
		if onDisconnect != nil {
			onDisconnect()
		}
	})

	ctx := context.Background()
	if err := client.ConnectWithKey(ctx); err != nil {
		result.ErrorMessage = err.Error()
		return result, fmt.Errorf("SSH auth failed: %w", err)
	}
	if err := client.StartPortForwarding(ctx); err != nil {
		_ = client.Close()
		result.ErrorMessage = err.Error()
		return result, fmt.Errorf("failed to start port forwarding: %w", err)
	}

	signerClient := signerclient.NewSignerClientWithToken(fmt.Sprintf("http://localhost:%d", localPort), token)
	s.Mu.Lock()
	signerClient.ProgressOut = s.SignerProgressOut
	s.Mu.Unlock()
	keysResp, err := signerClient.GetKeys()
	if err != nil {
		_ = client.Close()
		result.ErrorMessage = err.Error()
		return result, fmt.Errorf("failed to verify connection: %w", err)
	}

	s.Mu.Lock()
	s.SignerClient = signerClient
	s.ConnectionTarget = target
	s.SSHTunnelClient = client
	s.TunnelConnected = true
	s.TunnelCtx, s.TunnelCancel = context.WithCancel(context.Background())
	s.connectingTarget = ""
	s.Mu.Unlock()

	if onKeys != nil {
		onKeys(keysResp.Keys)
	}

	result.Connected = true
	result.Port = localPort
	result.KeyCount = keysResp.Count
	result.Locked = keysResp.Locked
	return result, nil
}

// Disconnect closes any active signer connection.
func (s *ConnectionState) Disconnect(onDisconnect func()) error {
	s.Mu.Lock()
	if s.SignerClient == nil {
		s.Mu.Unlock()
		return nil
	}
	if s.TunnelCancel != nil {
		s.TunnelCancel()
	}
	if s.SSHTunnelClient != nil {
		_ = s.SSHTunnelClient.Close()
	}
	s.clearLocked()
	s.Mu.Unlock()
	if onDisconnect != nil {
		onDisconnect()
	}
	return nil
}

// RequestToken requests a signer token over SSH.
func (s *ConnectionState) RequestToken(
	host string,
	sshPort int,
	identityFile string,
	knownHostsPath string,
	hostKeyApproval sshtunnel.HostKeyApprovalHandler,
	onProvisioningStart func(),
) (string, error) {
	client := sshtunnel.NewClient(host, sshPort, 0, 0, identityFile, knownHostsPath)
	if hostKeyApproval != nil {
		client.SetHostKeyApprovalHandler(hostKeyApproval)
	}
	if onProvisioningStart != nil {
		client.SetProvisioningStartCallback(onProvisioningStart)
	}
	ctx := context.Background()
	token, err := client.RequestToken(ctx, auth.CurrentProductIdentityID())
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	return token, nil
}

func (s *ConnectionState) clearLocked() {
	s.SSHTunnelClient = nil
	s.TunnelConnected = false
	s.SignerClient = nil
	s.ConnectionTarget = ""
	s.TunnelCtx = nil
	s.TunnelCancel = nil
	s.connectingTarget = ""
}
