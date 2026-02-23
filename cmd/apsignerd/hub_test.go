// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"testing"
)

// TestSignerStateString verifies SignerState.String() returns correct values
func TestSignerStateString(t *testing.T) {
	tests := []struct {
		state    SignerState
		expected string
	}{
		{SignerStateLocked, "locked"},
		{SignerStateUnlocked, "unlocked"},
		{SignerState(99), "unknown"}, // Invalid state
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.state.String()
			if result != tt.expected {
				t.Errorf("SignerState(%d).String() = %q, want %q", tt.state, result, tt.expected)
			}
		})
	}
}

// TestNewHub verifies hub initialization
func TestNewHub(t *testing.T) {
	signer := &Signer{}
	hub := NewHub(signer)

	if hub == nil {
		t.Fatal("NewHub returned nil")
	}

	if hub.signer != signer {
		t.Error("Hub signer reference incorrect")
	}

	if hub.state != SignerStateLocked {
		t.Errorf("Initial state should be locked, got %v", hub.state)
	}

	if hub.pendingRequests == nil {
		t.Error("pendingRequests map should be initialized")
	}

	if hub.HasClient() {
		t.Error("New hub should have no client connected")
	}
}

// TestHubIsUnlocked verifies unlock state checking
func TestHubIsUnlocked(t *testing.T) {
	signer := &Signer{}
	hub := NewHub(signer)

	// Initially locked
	if hub.IsUnlocked() {
		t.Error("New hub should be locked")
	}

	// Unlock
	hub.SetUnlocked()
	if !hub.IsUnlocked() {
		t.Error("Hub should be unlocked after SetUnlocked()")
	}

	// Verify state
	if hub.GetState() != SignerStateUnlocked {
		t.Errorf("GetState() = %v, want %v", hub.GetState(), SignerStateUnlocked)
	}
}

// TestHubHasClient verifies client connection tracking
func TestHubHasClient(t *testing.T) {
	signer := &Signer{}
	hub := NewHub(signer)

	// No client initially
	if hub.HasClient() {
		t.Error("New hub should have no client")
	}
}

// TestFailAllPendingRequests verifies pending requests are failed on disconnect
func TestFailAllPendingRequests(t *testing.T) {
	signer := &Signer{}
	hub := NewHub(signer)

	// Verify that failing with no pending requests doesn't panic
	hub.failAllPendingRequests("test disconnect")

	// Verify map is empty after fail
	hub.pendingRequestsLock.Lock()
	count := len(hub.pendingRequests)
	hub.pendingRequestsLock.Unlock()

	if count != 0 {
		t.Errorf("Expected 0 pending requests after failAll, got %d", count)
	}
}
