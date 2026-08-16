// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import "testing"

type stubConn struct{}

func (stubConn) ReadMessage() ([]byte, error) { return nil, nil }
func (stubConn) WriteMessage([]byte) error    { return nil }
func (stubConn) RemoteAddr() string           { return "stub" }
func (stubConn) Close() error                 { return nil }

func TestSessionManagerPreAuthBindsToScalarPending(t *testing.T) {
	manager := NewSessionManager()
	active := NewSession(stubConn{}, SessionDeps{})
	manager.active = active
	pending := NewSession(stubConn{}, SessionDeps{})
	if !manager.RegisterPreAuthPending(pending) {
		t.Fatal("RegisterPreAuthPending() = false, want true")
	}
	gotActive, ok := manager.BindPreAuthPending(pending)
	if !ok || gotActive != active {
		t.Fatalf("BindPreAuthPending() = (%p, %v), want (%p, true)", gotActive, ok, active)
	}
	if manager.preAuthPending != nil || manager.pending != pending {
		t.Fatal("pre-auth session did not move to the scalar pending slot")
	}
}

func TestSessionManagerHasOnePendingSlot(t *testing.T) {
	manager := NewSessionManager()
	first := NewSession(stubConn{}, SessionDeps{})
	second := NewSession(stubConn{}, SessionDeps{})
	if !manager.RegisterPending(first) || manager.RegisterPending(second) {
		t.Fatal("manager did not enforce one authenticated pending slot")
	}
	manager.ClearPending(first)
	if !manager.RegisterPending(second) {
		t.Fatal("cleared pending slot was not reusable")
	}
}

func TestSessionManagerPromoteReplaceAndClear(t *testing.T) {
	manager := NewSessionManager()
	first := NewSession(stubConn{}, SessionDeps{})
	second := NewSession(stubConn{}, SessionDeps{})
	if !manager.RegisterPending(first) {
		t.Fatal("RegisterPending(first) = false")
	}
	replaced, ok := manager.PromoteToActive(first)
	if !ok || replaced != nil || !manager.HasClient() || manager.ActiveSession() != first {
		t.Fatal("first promotion did not establish the scalar active slot")
	}
	if !manager.RegisterPending(second) {
		t.Fatal("RegisterPending(second) = false")
	}
	replaced, ok = manager.PromoteToActive(second)
	if !ok || replaced != first || manager.ActiveSession() != second {
		t.Fatal("second promotion did not atomically replace the active session")
	}
	if manager.ClearActive(first) || !manager.ClearActive(second) || manager.HasClient() {
		t.Fatal("ClearActive did not preserve pointer ownership")
	}
}

func TestSessionManagerRejectsSecondPreAuthPending(t *testing.T) {
	manager := NewSessionManager()
	first := NewSession(stubConn{}, SessionDeps{})
	second := NewSession(stubConn{}, SessionDeps{})
	if !manager.RegisterPreAuthPending(first) || manager.RegisterPreAuthPending(second) {
		t.Fatal("manager did not enforce one pre-auth pending slot")
	}
}
