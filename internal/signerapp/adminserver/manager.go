// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import "sync"

// SessionManager tracks active and pending admin sessions by identity.
// Local IPC sessions start in the pre-auth pending slot until auth resolves
// their target identity. Transports that already know the target identity can
// register directly into identity-scoped pending storage.
type SessionManager struct {
	mu             sync.Mutex
	active         map[string]*Session
	pending        map[string]*Session
	preAuthPending *Session
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		active:  make(map[string]*Session),
		pending: make(map[string]*Session),
	}
}

func (m *SessionManager) RegisterPreAuthPending(s *Session) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.preAuthPending != nil {
		return false
	}
	m.preAuthPending = s
	return true
}

func (m *SessionManager) RegisterPending(identityID string, s *Session) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if identityID == "" || m.pending[identityID] != nil {
		return false
	}
	m.pending[identityID] = s
	return true
}

func (m *SessionManager) MovePendingToIdentity(identityID string, s *Session) (active *Session, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if identityID == "" {
		return nil, false
	}

	switch {
	case m.pending[identityID] == s:
		return m.active[identityID], true
	case m.pending[identityID] != nil:
		return nil, false
	case m.preAuthPending == s:
		m.preAuthPending = nil
		m.pending[identityID] = s
		return m.active[identityID], true
	default:
		return nil, false
	}
}

func (m *SessionManager) PromoteToActive(identityID string, s *Session) (replaced *Session, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if identityID == "" {
		return nil, false
	}
	if m.pending[identityID] == s {
		delete(m.pending, identityID)
	}
	replaced = m.active[identityID]
	m.active[identityID] = s
	return replaced, true
}

func (m *SessionManager) ClearPending(identityID string, s *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if identityID != "" && m.pending[identityID] == s {
		delete(m.pending, identityID)
	}
}

func (m *SessionManager) ClearPreAuthPending(s *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.preAuthPending == s {
		m.preAuthPending = nil
	}
}

func (m *SessionManager) ClearActive(identityID string, s *Session) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if identityID == "" || m.active[identityID] != s {
		return false
	}
	delete(m.active, identityID)
	return true
}

func (m *SessionManager) HasClient(identityID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return identityID != "" && m.active[identityID] != nil
}

func (m *SessionManager) ActiveSession(identityID string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	if identityID == "" {
		return nil
	}
	return m.active[identityID]
}
