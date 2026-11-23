// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package connect

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// ErrAlreadyConnected indicates a connect attempt while a connection to a
// different target is active. Wrapped errors carry the current target.
var ErrAlreadyConnected = errors.New("already connected")

// Result reports a successful remote signer connection.
type Result struct {
	// AlreadyConnected reports that the target was already connected and
	// nothing new was opened.
	AlreadyConnected bool
	Target           string
	KeyCount         int
	Locked           bool
}

// signerSSHHTTPAuthority is the host the signer client's requests name. They
// never leave the process: the transport carries each connection over an SSH
// channel (DialSignerAPI), so nothing listens on this machine.
const signerSSHHTTPAuthority = "signer.aplane.invalid:80"

// ConnectWithTunnel establishes an SSH connection authenticated by the
// client's enrolled key and verifies the signer answers over it. The signer
// client opens an SSH channel for each HTTP connection; no local port is
// opened, so another process on this machine cannot use the connection.
// ctx bounds the setup, which ends when it does; the connection, kept after
// the command that made it, has a lifetime of its own that Disconnect ends.
func (s *ConnectionState) ConnectWithTunnel(
	ctx context.Context,
	target string,
	host string,
	sshPort int,
	identityFile string,
	knownHostsPath string,
	hostKeyApproval sshtunnel.HostKeyApprovalHandler,
	onKeys func([]signerapi.KeyInfo) error,
	onDisconnect func(),
) (*Result, error) {
	alreadyConnected, currentTarget, inProgress := s.beginConnect(target)
	if alreadyConnected {
		return &Result{AlreadyConnected: true, Target: target}, nil
	}
	if inProgress {
		if currentTarget == target {
			return nil, fmt.Errorf("connection to %s already in progress", target)
		}
		return nil, fmt.Errorf("already connecting to %s", currentTarget)
	}
	if currentTarget != "" {
		return nil, fmt.Errorf("%w to %s", ErrAlreadyConnected, currentTarget)
	}

	connected := false
	defer func() {
		if !connected {
			s.clearPendingConnect(target)
		}
	}()
	client := sshtunnel.NewClient(host, sshPort, identityFile, knownHostsPath)
	client.SetHostKeyApprovalHandler(hostKeyApproval)
	client.SetIdentityCreatedCallback(s.IdentityCreatedHandler())

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

	sshCtx, cancelSSH, detachSetup := newSSHLifetime(ctx)
	if err := client.ConnectWithKey(sshCtx); err != nil {
		_ = detachSetup()
		cancelSSH()
		return nil, fmt.Errorf("SSH auth failed: %w", err)
	}
	if err := detachSetup(); err != nil {
		cancelSSH()
		_ = client.Close()
		return nil, fmt.Errorf("SSH setup canceled: %w", err)
	}
	failed := func() {
		cancelSSH()
		_ = client.Close()
	}

	signerClient := signerclient.NewSignerClient("http://" + signerSSHHTTPAuthority)
	signerClient.Client = &http.Client{Transport: newSSHHTTPTransport(client, signerSSHHTTPAuthority)}
	keysResp, err := signerClient.GetKeysWithContext(ctx)
	if err != nil {
		failed()
		switch client.DisconnectReason() {
		case sshtunnel.DisconnectReasonConnectionLimit:
			return nil, fmt.Errorf("signer connection limit reached")
		case sshtunnel.DisconnectReasonKeyRevoked:
			return nil, fmt.Errorf("client key was revoked by the signer")
		}
		return nil, fmt.Errorf("failed to verify connection: %w", err)
	}
	if onKeys != nil {
		if err := onKeys(keysResp.Keys); err != nil {
			failed()
			return nil, fmt.Errorf("invalid signer key inventory: %w", err)
		}
	}

	s.Mu.Lock()
	s.SignerClient = signerClient
	s.ConnectionTarget = target
	s.SSHTunnelClient = client
	s.TunnelCancel = cancelSSH
	s.connectingTarget = ""
	s.Mu.Unlock()

	connected = true
	return &Result{Target: target, KeyCount: len(keysResp.Keys), Locked: keysResp.Locked}, nil
}

// Disconnect closes any active signer connection.
func (s *ConnectionState) Disconnect(onDisconnect func()) {
	s.Mu.Lock()
	if s.SignerClient == nil {
		s.Mu.Unlock()
		return
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
}

// EnrollmentResult is a node's answer to an enrollment request: the client
// key's fingerprint and whether the request now waits for the operator.
type EnrollmentResult = sshtunnel.EnrollmentResult

// RequestEnrollmentWithContext asks a node to enroll this client's SSH key.
// The request is queued for the operator; the answer says whether it is
// pending or the key was already enrolled.
func (s *ConnectionState) RequestEnrollmentWithContext(
	ctx context.Context,
	host string,
	sshPort int,
	identityFile string,
	knownHostsPath string,
	label string,
	hostKeyApproval sshtunnel.HostKeyApprovalHandler,
	onEnrollmentStart func(string),
) (EnrollmentResult, error) {
	client := sshtunnel.NewClient(host, sshPort, identityFile, knownHostsPath)
	client.SetHostKeyApprovalHandler(hostKeyApproval)
	client.SetIdentityCreatedCallback(s.IdentityCreatedHandler())
	client.SetEnrollmentStartCallback(onEnrollmentStart)
	result, err := client.RequestEnrollment(ctx, label)
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("enrollment request failed: %w", err)
	}
	return result, nil
}

func (s *ConnectionState) clearLocked() {
	if s.TunnelCancel != nil {
		s.TunnelCancel()
	}
	if s.SignerClient != nil && s.SignerClient.Client != nil {
		s.SignerClient.Client.CloseIdleConnections()
	}
	s.SSHTunnelClient = nil
	s.SignerClient = nil
	s.ConnectionTarget = ""
	s.TunnelCancel = nil
	s.connectingTarget = ""
}
