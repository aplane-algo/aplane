// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminproto

import "testing"

type stubConn struct{}

func (stubConn) ReadMessage() ([]byte, error) { return nil, nil }
func (stubConn) WriteMessage([]byte) error    { return nil }
func (stubConn) RemoteAddr() string           { return "stub" }
func (stubConn) Close() error                 { return nil }

func TestSessionManagerRegisterPendingAndGetActive(t *testing.T) {
	manager := NewSessionManager()
	active := NewSession(stubConn{}, SessionDeps{})
	manager.active["alice"] = active

	pending := NewSession(stubConn{}, SessionDeps{})
	if !manager.RegisterPreAuthPending(pending) {
		t.Fatal("RegisterPreAuthPending() = false, want true")
	}
	gotActive, ok := manager.MovePendingToIdentity("alice", pending)
	if !ok {
		t.Fatal("MovePendingToIdentity() = false, want true")
	}
	if gotActive != active {
		t.Fatal("MovePendingToIdentity() returned wrong active session")
	}
}

func TestSessionManagerRejectsSecondPreAuthPending(t *testing.T) {
	manager := NewSessionManager()
	pending := NewSession(stubConn{}, SessionDeps{})
	other := NewSession(stubConn{}, SessionDeps{})

	if !manager.RegisterPreAuthPending(pending) {
		t.Fatal("RegisterPreAuthPending() = false, want true")
	}
	if manager.RegisterPreAuthPending(other) {
		t.Fatal("second RegisterPreAuthPending() = true, want false")
	}
}

func TestSessionManagerPromoteClearAndHasClient(t *testing.T) {
	manager := NewSessionManager()
	session := NewSession(stubConn{}, SessionDeps{})

	if !manager.RegisterPending("alice", session) {
		t.Fatal("RegisterPending() = false, want true")
	}

	replaced, ok := manager.PromoteToActive("alice", session)
	if !ok {
		t.Fatal("PromoteToActive() = false, want true")
	}
	if replaced != nil {
		t.Fatal("PromoteToActive() replaced != nil, want nil")
	}
	if !manager.HasClient("alice") {
		t.Fatal("HasClient() = false, want true")
	}
	if manager.ActiveSession("alice") != session {
		t.Fatal("ActiveSession() returned wrong session")
	}

	if manager.ClearActive("alice", NewSession(stubConn{}, SessionDeps{})) {
		t.Fatal("ClearActive(other) = true, want false")
	}
	if !manager.ClearActive("alice", session) {
		t.Fatal("ClearActive(session) = false, want true")
	}
	if manager.HasClient("alice") {
		t.Fatal("HasClient() = true, want false")
	}
}

func TestSessionManagerAllowsActiveSessionsForDifferentIdentities(t *testing.T) {
	manager := NewSessionManager()
	alice := NewSession(stubConn{}, SessionDeps{})
	bob := NewSession(stubConn{}, SessionDeps{})

	if !manager.RegisterPending("alice", alice) {
		t.Fatal("RegisterPending(alice) = false, want true")
	}
	if !manager.RegisterPending("bob", bob) {
		t.Fatal("RegisterPending(bob) = false, want true")
	}
	if _, ok := manager.PromoteToActive("alice", alice); !ok {
		t.Fatal("PromoteToActive(alice) = false, want true")
	}
	if _, ok := manager.PromoteToActive("bob", bob); !ok {
		t.Fatal("PromoteToActive(bob) = false, want true")
	}

	if manager.ActiveSession("alice") != alice {
		t.Fatal("ActiveSession(alice) returned wrong session")
	}
	if manager.ActiveSession("bob") != bob {
		t.Fatal("ActiveSession(bob) returned wrong session")
	}
	if !manager.HasClient("alice") || !manager.HasClient("bob") {
		t.Fatal("HasClient() = false for active identity")
	}
}

func TestSessionManagerPendingIsIdentityScoped(t *testing.T) {
	manager := NewSessionManager()
	alicePending := NewSession(stubConn{}, SessionDeps{})
	bobPending := NewSession(stubConn{}, SessionDeps{})

	if !manager.RegisterPending("alice", alicePending) {
		t.Fatal("RegisterPending(alice) = false, want true")
	}
	if !manager.RegisterPending("bob", bobPending) {
		t.Fatal("RegisterPending(bob) = false, want true")
	}
	if manager.RegisterPending("alice", NewSession(stubConn{}, SessionDeps{})) {
		t.Fatal("second RegisterPending(alice) = true, want false")
	}
	if _, ok := manager.PromoteToActive("bob", bobPending); !ok {
		t.Fatal("PromoteToActive(bob) = false, want true")
	}
	if !manager.HasClient("bob") {
		t.Fatal("HasClient(bob) = false, want true")
	}
	if manager.HasClient("alice") {
		t.Fatal("HasClient(alice) = true, want false")
	}
}

func TestSessionManagerSecondSessionSeesActiveForSameIdentity(t *testing.T) {
	manager := NewSessionManager()
	active := NewSession(stubConn{}, SessionDeps{})
	next := NewSession(stubConn{}, SessionDeps{})

	if !manager.RegisterPending("alice", active) {
		t.Fatal("RegisterPending(active) = false, want true")
	}
	if _, ok := manager.PromoteToActive("alice", active); !ok {
		t.Fatal("PromoteToActive(active) = false, want true")
	}
	if !manager.RegisterPreAuthPending(next) {
		t.Fatal("RegisterPreAuthPending(next) = false, want true")
	}

	gotActive, ok := manager.MovePendingToIdentity("alice", next)
	if !ok {
		t.Fatal("MovePendingToIdentity(next) = false, want true")
	}
	if gotActive != active {
		t.Fatal("MovePendingToIdentity(next) did not return active alice session")
	}
}

func TestSessionManagerClearActiveDoesNotClearOtherIdentity(t *testing.T) {
	manager := NewSessionManager()
	alice := NewSession(stubConn{}, SessionDeps{})
	bob := NewSession(stubConn{}, SessionDeps{})

	_ = manager.RegisterPending("alice", alice)
	_, _ = manager.PromoteToActive("alice", alice)
	_ = manager.RegisterPending("bob", bob)
	_, _ = manager.PromoteToActive("bob", bob)

	if !manager.ClearActive("alice", alice) {
		t.Fatal("ClearActive(alice) = false, want true")
	}
	if manager.ActiveSession("alice") != nil {
		t.Fatal("ActiveSession(alice) != nil, want nil")
	}
	if manager.ActiveSession("bob") != bob {
		t.Fatal("ActiveSession(bob) changed after clearing alice")
	}
}
