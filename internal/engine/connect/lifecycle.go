// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package connect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// ErrAlreadyConnected indicates a connect attempt while a connection to a
// different target is active. Wrapped errors carry the current target.
var ErrAlreadyConnected = errors.New("already connected")

// Result reports the outcome of a remote signer connection attempt.
type Result struct {
	Connected    bool
	Target       string
	Port         int
	KeyCount     int
	Locked       bool
	ErrorMessage string
}

// ConnectWithTunnel establishes an SSH tunnel connection authenticated by the
// client's enrolled key and verifies the signer answers over it.
func (s *ConnectionState) ConnectWithTunnel(
	target string,
	host string,
	sshPort int,
	localPort int,
	identityFile string,
	knownHostsPath string,
	hostKeyApproval sshtunnel.HostKeyApprovalHandler,
	onKeys func([]signerapi.KeyInfo) error,
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
		return nil, fmt.Errorf("%w to %s", ErrAlreadyConnected, currentTarget)
	}

	result := &Result{Target: target}
	defer func() {
		if !result.Connected {
			s.clearPendingConnect(target)
		}
	}()
	dialTimeout := s.portDialTimeout
	if dialTimeout == nil {
		dialTimeout = net.DialTimeout
	}
	conn, err := dialTimeout("tcp", fmt.Sprintf("localhost:%d", localPort), 100*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return result, fmt.Errorf("port %d is already in use locally", localPort)
	}

	client := sshtunnel.NewClient(host, sshPort, localPort, identityFile, knownHostsPath)
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

	signerClient := signerclient.NewSignerClient(fmt.Sprintf("http://localhost:%d", localPort))
	s.Mu.Lock()
	signerClient.ProgressOut = s.SignerProgressOut
	s.Mu.Unlock()
	keysResp, err := signerClient.GetKeys()
	if err != nil {
		_ = client.Close()
		result.ErrorMessage = err.Error()
		return result, fmt.Errorf("failed to verify connection: %w", err)
	}
	if onKeys != nil {
		if err := onKeys(keysResp.Keys); err != nil {
			_ = client.Close()
			result.ErrorMessage = err.Error()
			return result, fmt.Errorf("invalid signer key inventory: %w", err)
		}
	}

	s.Mu.Lock()
	s.SignerClient = signerClient
	s.ConnectionTarget = target
	s.SSHTunnelClient = client
	s.TunnelConnected = true
	s.TunnelCtx, s.TunnelCancel = context.WithCancel(context.Background())
	s.connectingTarget = ""
	s.Mu.Unlock()

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
	client := sshtunnel.NewClient(host, sshPort, 0, identityFile, knownHostsPath)
	if hostKeyApproval != nil {
		client.SetHostKeyApprovalHandler(hostKeyApproval)
	}
	if onEnrollmentStart != nil {
		client.SetEnrollmentStartCallback(onEnrollmentStart)
	}
	result, err := client.RequestEnrollment(ctx, label)
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("enrollment request failed: %w", err)
	}
	return result, nil
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
