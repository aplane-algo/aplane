// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import "sync"

// SessionManager tracks the process-wide active and pending admin sessions.
// Local IPC sessions start in the pre-auth pending slot. SSH sessions enter
// the authenticated pending slot directly.
type SessionManager struct {
	mu             sync.Mutex
	active         *Session
	pending        *Session
	preAuthPending *Session
}

func NewSessionManager() *SessionManager {
	return &SessionManager{}
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

func (m *SessionManager) RegisterPending(s *Session) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending != nil {
		return false
	}
	m.pending = s
	return true
}

func (m *SessionManager) BindPreAuthPending(s *Session) (active *Session, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch {
	case m.pending == s:
		return m.active, true
	case m.pending != nil:
		return nil, false
	case m.preAuthPending == s:
		m.preAuthPending = nil
		m.pending = s
		return m.active, true
	default:
		return nil, false
	}
}

func (m *SessionManager) PromoteToActive(s *Session) (replaced *Session, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == s {
		m.pending = nil
	}
	replaced = m.active
	m.active = s
	return replaced, true
}

func (m *SessionManager) ClearPending(s *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == s {
		m.pending = nil
	}
}

func (m *SessionManager) ClearPreAuthPending(s *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.preAuthPending == s {
		m.preAuthPending = nil
	}
}

func (m *SessionManager) ClearActive(s *Session) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active != s {
		return false
	}
	m.active = nil
	return true
}

func (m *SessionManager) HasClient() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active != nil
}

func (m *SessionManager) ActiveSession() *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}
