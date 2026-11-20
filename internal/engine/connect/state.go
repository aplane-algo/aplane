// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package connect

import (
	"context"
	"sync"

	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

// ConnectionState owns remote-signer connection lifecycle state for the engine.
type ConnectionState struct {
	Mu sync.Mutex

	SignerClient     *signerclient.Client
	SSHTunnelClient  *sshtunnel.Client
	TunnelCancel     context.CancelFunc
	ConnectionTarget string
	connectingTarget string
	identityCreated  func(sshtunnel.IdentityCreated)
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

// Snapshot reports whether a signer client is active and the target it
// serves, read under one lock so a concurrent disconnect cannot split them.
func (s *ConnectionState) Snapshot() (connected bool, target string) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	return s.SignerClient != nil, s.ConnectionTarget
}

// GetConnectionTarget returns the active connection target.
func (s *ConnectionState) GetConnectionTarget() string {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	return s.ConnectionTarget
}

// SetIdentityCreatedHandler sets what happens when connecting generates a new SSH
// identity key, for every connection made from now on.
func (s *ConnectionState) SetIdentityCreatedHandler(handler func(sshtunnel.IdentityCreated)) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.identityCreated = handler
}

// IdentityCreatedHandler returns the handler set by SetIdentityCreatedHandler.
func (s *ConnectionState) IdentityCreatedHandler() func(sshtunnel.IdentityCreated) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	return s.identityCreated
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
