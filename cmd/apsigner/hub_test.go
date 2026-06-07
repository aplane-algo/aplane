// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
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

func TestRegistryInitializesSignerRuntime(t *testing.T) {
	signer := &Signer{
		registry: identity.NewRegistry(),
	}

	ir := identity.New(identity.Config{
		Authenticator: auth.NewTokenAuthenticator("test-token"),
		ID:            auth.DefaultIdentityID,
	})
	_ = signer.registry.Register(ir)
	signer.wireApprovalCoordinator(ir)

	if signer.registry.Get(auth.DefaultIdentityID) == nil {
		t.Fatal("registry did not store identity runtime")
	}

	if signer.getState() != SignerStateLocked {
		t.Errorf("Initial state should be locked, got %v", signer.getState())
	}

	if ir.Approval() == nil {
		t.Error("approval coordinator should be initialized")
	}

	if signer.hasClient() {
		t.Error("new signer should have no client connected")
	}
}

func TestSignerIsUnlocked(t *testing.T) {
	signer := &Signer{
		registry: identity.NewRegistry(),
	}

	ir := identity.New(identity.Config{
		Authenticator: auth.NewTokenAuthenticator("test-token"),
		ID:            auth.DefaultIdentityID,
	})
	_ = signer.registry.Register(ir)

	// Initially locked
	if signer.isUnlocked() {
		t.Error("new signer should be locked")
	}

	// Unlock
	signer.setUnlocked()
	if !signer.isUnlocked() {
		t.Error("signer should be unlocked after setUnlocked()")
	}

	// Verify state
	if signer.getState() != SignerStateUnlocked {
		t.Errorf("getState() = %v, want %v", signer.getState(), SignerStateUnlocked)
	}
}

func TestSignerHasClient(t *testing.T) {
	signer := &Signer{}

	// No client initially
	if signer.hasClient() {
		t.Error("new signer should have no client")
	}
}

// TestFailAllPendingRequests verifies pending requests are failed on disconnect
func TestFailAllPendingRequests(t *testing.T) {
	signer := &Signer{
		registry: identity.NewRegistry(),
	}

	ir := identity.New(identity.Config{
		Authenticator: auth.NewTokenAuthenticator("test-token"),
		ID:            auth.DefaultIdentityID,
	})
	_ = signer.registry.Register(ir)
	signer.wireApprovalCoordinator(ir)

	// Verify that failing with no pending requests doesn't panic
	signer.failAllPendingApprovals("test disconnect")

	// Verify map is empty after fail
	count := signer.pendingSignCount()
	if count != 0 {
		t.Errorf("Expected 0 pending requests after failAll, got %d", count)
	}
}

func TestRequestSigningApprovalTimeoutCleansPendingRequest(t *testing.T) {
	signer := &Signer{
		registry: identity.NewRegistry(),
	}

	ir := identity.New(identity.Config{
		Authenticator: auth.NewTokenAuthenticator("test-token"),
		ID:            auth.DefaultIdentityID,
	})
	_ = signer.registry.Register(ir)
	signer.wireApprovalCoordinator(ir)
	signer.ipcServer = newIPCServerWithActiveConn(&hubStubConn{})

	approved, err := signer.requestSigningApproval(auth.DefaultIdentityID, "req-timeout", "ADDR", "SENDER", "desc", 1, 2, nil, 10*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if approved {
		t.Fatal("approved = true, want false")
	}

	count := signer.pendingSignCount()
	if count != 0 {
		t.Fatalf("pendingRequests count = %d, want 0", count)
	}
}

func TestApprovalCoordinatorRoutesHubCallsByIdentity(t *testing.T) {
	hub := &recordingAdminHub{}
	signer := &Signer{
		registry: identity.NewRegistry(),
		hub:      hub,
	}

	ir := identity.New(identity.Config{
		Authenticator: auth.NewTokenAuthenticator("test-token"),
		ID:            "alice",
	})
	_ = signer.registry.Register(ir)
	signer.wireApprovalCoordinator(ir)

	approved, err := signer.requestSigningApproval("alice", "req-sign", "ADDR", "SENDER", "desc", 1, 2, nil, time.Second)
	if err == nil {
		t.Fatal("expected send failure, got nil")
	}
	if approved {
		t.Fatal("approved = true, want false")
	}
	if hub.hasClientIdentity != "alice" {
		t.Fatalf("HasClient identity = %q, want alice", hub.hasClientIdentity)
	}
	if hub.signIdentity != "alice" {
		t.Fatalf("SendSignRequest identity = %q, want alice", hub.signIdentity)
	}

	hub.reset()
	approved, err = signer.requestTokenProvisioning("req-token", "alice", "fingerprint", "remote", time.Second)
	if err == nil {
		t.Fatal("expected send failure, got nil")
	}
	if approved {
		t.Fatal("approved = true, want false")
	}
	if hub.hasClientIdentity != "alice" {
		t.Fatalf("HasClient identity = %q, want alice", hub.hasClientIdentity)
	}
	if hub.tokenIdentity != "alice" {
		t.Fatalf("SendTokenProvisioningRequest identity = %q, want alice", hub.tokenIdentity)
	}
}

func TestReloadServiceRoutesKeysChangedByIdentity(t *testing.T) {
	hub := &recordingAdminHub{}
	signer := &Signer{hub: hub}
	ir := identity.New(identity.Config{
		Authenticator: auth.NewTokenAuthenticator("test-token"),
		ID:            "alice",
	})

	svc := signer.newReloadServiceForIdentity(ir, nil)
	if svc.NotifyKeysChanged == nil {
		t.Fatal("NotifyKeysChanged = nil, want configured callback")
	}
	svc.NotifyKeysChanged(signertemplates.KeysChangedNotification{KeyCount: 3})

	if hub.keysIdentity != "alice" {
		t.Fatalf("NotifyKeysChanged identity = %q, want alice", hub.keysIdentity)
	}
}

func TestReloadServiceClosesRegistryOnNodeRoleConflict(t *testing.T) {
	reg := identity.NewRegistry()
	signer := &Signer{registry: reg}
	ir := identity.New(identity.Config{
		Authenticator: auth.NewTokenAuthenticator("test-token"),
		ID:            "alice",
		NodeRole:      noderole.RoleSigner,
	})

	svc := signer.newReloadServiceForIdentity(ir, nil)
	err := svc.BeforePublish(nil, map[string]string{
		"75OU3CR55IDLKDFEZSFWLIRGE2I5Q337D3NTKAEHJ6K7FGYON5AA": keytypes.AttestorComponentEd25519V1,
	}, nil)
	if err == nil {
		t.Fatal("BeforePublish() error = nil, want node role conflict")
	}
	if closeErr := reg.CloseError(); !errors.Is(closeErr, identity.ErrRegistryClosed) {
		t.Fatalf("registry CloseError() = %v, want ErrRegistryClosed", closeErr)
	}
}

func TestApprovalServiceChecksClientForTargetIdentity(t *testing.T) {
	hub := &recordingAdminHub{}
	signer := &Signer{
		registry: identity.NewRegistry(),
		hub:      hub,
	}
	ir := identity.New(identity.Config{
		Authenticator: auth.NewTokenAuthenticator("test-token"),
		ID:            "alice",
	})
	_ = signer.registry.Register(ir)

	svc := signer.newApprovalServiceForIdentity(ir)
	if svc.HasClient == nil {
		t.Fatal("ApprovalService.HasClient = nil, want identity-aware callback")
	}
	if !svc.HasClient("alice") {
		t.Fatal("ApprovalService.HasClient(alice) = false, want true")
	}
	if hub.hasClientIdentity != "alice" {
		t.Fatalf("HasClient identity = %q, want alice", hub.hasClientIdentity)
	}
}

func TestRequestSigningApprovalDisconnectCleansPendingRequest(t *testing.T) {
	signer := &Signer{
		registry: identity.NewRegistry(),
	}

	ir := identity.New(identity.Config{
		Authenticator: auth.NewTokenAuthenticator("test-token"),
		ID:            auth.DefaultIdentityID,
	})
	_ = signer.registry.Register(ir)
	signer.wireApprovalCoordinator(ir)
	signer.ipcServer = newIPCServerWithActiveConn(&hubStubConn{})

	done := make(chan struct{})
	var approved bool
	var err error
	go func() {
		defer close(done)
		approved, err = signer.requestSigningApproval(auth.DefaultIdentityID, "req-disconnect", "ADDR", "SENDER", "desc", 1, 2, nil, time.Second)
	}()

	deadline := time.Now().Add(200 * time.Millisecond)
	for {
		count := signer.pendingSignCount()
		if count == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pending request was not registered in time")
		}
		time.Sleep(time.Millisecond)
	}

	signer.failAllPendingApprovals("disconnect")
	<-done

	if err != nil {
		t.Fatalf("expected nil error after disconnect cleanup, got %v", err)
	}
	if approved {
		t.Fatal("approved = true, want false")
	}

	count := signer.pendingSignCount()
	if count != 0 {
		t.Fatalf("pendingRequests count = %d, want 0", count)
	}
}

func TestTryUnlockInvalidPassphraseLeavesSignerLocked(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	server.lock()

	ir := server.registry.Get(auth.DefaultIdentityID)
	success, keyCount, errMsg := ir.TryUnlock([]byte("wrong-passphrase"), nil)
	if success {
		t.Fatal("success = true, want false")
	}
	if keyCount != 0 {
		t.Fatalf("keyCount = %d, want 0", keyCount)
	}
	if errMsg != "invalid passphrase" {
		t.Fatalf("errMsg = %q, want %q", errMsg, "invalid passphrase")
	}
	if server.isUnlocked() {
		t.Fatal("signer should remain locked after invalid passphrase")
	}
}

type hubStubConn struct{}

func (s *hubStubConn) Read([]byte) (int, error)         { return 0, nil }
func (s *hubStubConn) Write(b []byte) (int, error)      { return len(b), nil }
func (s *hubStubConn) Close() error                     { return nil }
func (s *hubStubConn) LocalAddr() net.Addr              { return nil }
func (s *hubStubConn) RemoteAddr() net.Addr             { return nil }
func (s *hubStubConn) SetDeadline(time.Time) error      { return nil }
func (s *hubStubConn) SetReadDeadline(time.Time) error  { return nil }
func (s *hubStubConn) SetWriteDeadline(time.Time) error { return nil }

type recordingAdminHub struct {
	hasClientIdentity string
	signIdentity      string
	cancelIdentity    string
	tokenIdentity     string
	lockedIdentity    string
	keysIdentity      string
}

func (h *recordingAdminHub) reset() {
	*h = recordingAdminHub{}
}

func (h *recordingAdminHub) HasClient(identityID string) bool {
	h.hasClientIdentity = identityID
	return true
}

func (h *recordingAdminHub) SendSignRequest(identityID string, _ *signerapproval.SignRequest) bool {
	h.signIdentity = identityID
	return false
}

func (h *recordingAdminHub) SendSignRequestCanceled(identityID string, _ *signerapproval.SignRequestCanceled) bool {
	h.cancelIdentity = identityID
	return false
}

func (h *recordingAdminHub) SendTokenProvisioningRequest(identityID string, _ *signerapproval.TokenProvisioningRequest) bool {
	h.tokenIdentity = identityID
	return false
}

func (h *recordingAdminHub) NotifyLocked(identityID string, _ adminproto.SignerLockedNotification) {
	h.lockedIdentity = identityID
}

func (h *recordingAdminHub) NotifyKeysChanged(identityID string, _ adminproto.KeysChangedNotification) {
	h.keysIdentity = identityID
}
