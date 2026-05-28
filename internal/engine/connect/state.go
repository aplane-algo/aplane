// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package connect

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

// ConnectionState owns remote-signer connection lifecycle state for the engine.
type ConnectionState struct {
	Mu sync.Mutex

	SignerClient      *signerclient.Client
	SignerProgressOut io.Writer
	SSHTunnelClient   *sshtunnel.Client
	TunnelConnected   bool
	TunnelCtx         context.Context
	TunnelCancel      context.CancelFunc
	ConnectionTarget  string
	connectingTarget  string
	portDialTimeout   func(network, address string, timeout time.Duration) (net.Conn, error)
}

// NewState creates an empty connection state.
func NewState() *ConnectionState {
	return &ConnectionState{}
}

// IsConnected reports whether a signer client is active.
func (s *ConnectionState) IsConnected() bool {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	return s.SignerClient != nil
}

// IsTunnelConnected reports whether an SSH tunnel connection is active.
func (s *ConnectionState) IsTunnelConnected() bool {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	return s.TunnelConnected
}

// GetConnectionTarget returns the active connection target.
func (s *ConnectionState) GetConnectionTarget() string {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	return s.ConnectionTarget
}

// SetSignerProgressWriter updates the output writer used by the current signer client
// for approval/progress messages.
func (s *ConnectionState) SetSignerProgressWriter(w io.Writer) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.SignerProgressOut = w
	if s.SignerClient != nil {
		s.SignerClient.ProgressOut = w
	}
}

// BindSignerClientContext attaches a request context to the current signer
// client, when one is connected. The returned cleanup function restores the
// previous client context.
func (s *ConnectionState) BindSignerClientContext(ctx context.Context) func() {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	if s.SignerClient == nil {
		return func() {}
	}
	client := s.SignerClient
	previous := client.Context()
	client.SetContext(ctx)
	return func() {
		client.SetContext(previous)
	}
}

func (s *ConnectionState) beginConnect(target string) (alreadyConnected bool, currentTarget string, inProgress bool) {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	if s.SignerClient != nil {
		return s.ConnectionTarget == target, s.ConnectionTarget, false
	}
	if s.connectingTarget != "" {
		return false, s.connectingTarget, true
	}
	s.connectingTarget = target
	return false, "", false
}

func (s *ConnectionState) clearPendingConnect(target string) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if s.connectingTarget == target {
		s.connectingTarget = ""
	}
}
