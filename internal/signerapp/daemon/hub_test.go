// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/noderole"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/witness"
)

// TestSignerStateString verifies SignerState.String() returns correct values
func TestSignerStateString(t *testing.T) {
	tests := []struct {
		state    SignerState
		expected string
	}{
		{SignerStateLocked, "locked"},
		{SignerStateUnlocked, "unlocked"},
		{SignerStateRecovery, "recovery"},
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
	signer := &Signer{}

	ir := productruntime.New(productruntime.Config{
		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})
	signer.runtime = ir
	signerstartup.WireApprovalCoordinator(ir, signer.productBuildHooks())

	if signer.productRuntime() == nil {
		t.Fatal("registry did not store product runtime")
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
	signer := &Signer{}

	ir := productruntime.New(productruntime.Config{
		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})
	signer.runtime = ir

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
	signer := &Signer{}

	ir := productruntime.New(productruntime.Config{
		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})
	signer.runtime = ir
	signerstartup.WireApprovalCoordinator(ir, signer.productBuildHooks())

	// Verify that failing with no pending requests doesn't panic
	signer.failAllPendingApprovals("test disconnect")

	// Verify map is empty after fail
	count := signer.pendingSignCount()
	if count != 0 {
		t.Errorf("Expected 0 pending requests after failAll, got %d", count)
	}
}

func TestRequestSigningApprovalTimeoutCleansPendingRequest(t *testing.T) {
	signer := &Signer{}

	ir := productruntime.New(productruntime.Config{
		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})
	signer.runtime = ir
	signerstartup.WireApprovalCoordinator(ir, signer.productBuildHooks())
	signer.ipcServer = newIPCServerWithActiveConn(&hubStubConn{})

	approved, err := ir.RequestSigningApproval("req-timeout", "ADDR", "SENDER", "desc", 1, 2, nil, 10*time.Millisecond)
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

func TestApprovalCoordinatorUsesProductAdminHub(t *testing.T) {
	hub := &recordingAdminHub{}
	signer := &Signer{
		hub: hub,
	}

	ir := productruntime.New(productruntime.Config{
		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})
	signer.runtime = ir
	signerstartup.WireApprovalCoordinator(ir, signer.productBuildHooks())

	approved, err := ir.RequestSigningApproval("req-sign", "ADDR", "SENDER", "desc", 1, 2, nil, time.Second)
	if err == nil {
		t.Fatal("expected send failure, got nil")
	}
	if approved {
		t.Fatal("approved = true, want false")
	}
	if !hub.hasClientCalled {
		t.Fatal("HasClient was not called")
	}
	if !hub.signCalled {
		t.Fatal("SendSignRequest was not called")
	}

	hub.reset()
	approved, err = signer.requestTokenProvisioning("req-token", "fingerprint", "remote", time.Second)
	if err == nil {
		t.Fatal("expected send failure, got nil")
	}
	if approved {
		t.Fatal("approved = true, want false")
	}
	if !hub.hasClientCalled {
		t.Fatal("HasClient was not called")
	}
	if !hub.tokenCalled {
		t.Fatal("SendTokenProvisioningRequest was not called")
	}
}

func TestReloadServiceNotifiesProductAdminHub(t *testing.T) {
	hub := &recordingAdminHub{}
	signer := &Signer{hub: hub}
	ir := productruntime.New(productruntime.Config{
		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})

	svc := signerstartup.NewReloadService(ir, testProductBuildOptions(signer), signer.productBuildHooks(), nil)
	if svc.NotifyKeysChanged == nil {
		t.Fatal("NotifyKeysChanged = nil, want configured callback")
	}
	svc.NotifyKeysChanged(signertemplates.KeysChangedNotification{KeyCount: 3})

	if !hub.keysCalled {
		t.Fatal("NotifyKeysChanged was not called")
	}
}

func TestReloadServiceFailsNodeClosedOnNodeRoleConflict(t *testing.T) {
	nodeState := &productruntime.NodeFailState{}
	signer := &Signer{nodeFailState: nodeState}
	ir := productruntime.New(productruntime.Config{
		Authenticator: auth.NewTokenAuthenticator("test-token"),

		NodeRole: noderole.RoleSigner,
	})

	svc := signerstartup.NewReloadService(ir, testProductBuildOptions(signer), signer.productBuildHooks(), nil)
	err := svc.BeforePublish(nil, map[string]string{
		"75OU3CR55IDLKDFEZSFWLIRGE2I5Q337D3NTKAEHJ6K7FGYON5AA": witness.Falcon1024V1,
	})
	if err == nil {
		t.Fatal("BeforePublish() error = nil, want node role conflict")
	}
	if closeErr := nodeState.Err(); !errors.Is(closeErr, productruntime.ErrNodeFailClosed) {
		t.Fatalf("node failure = %v, want ErrNodeFailClosed", closeErr)
	}
}

func TestApprovalServiceChecksProductAdminClient(t *testing.T) {
	hub := &recordingAdminHub{}
	signer := &Signer{
		hub: hub,
	}
	ir := productruntime.New(productruntime.Config{
		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})
	signer.runtime = ir

	svc := signer.newApprovalServiceForRuntime(ir)
	if svc.HasClient == nil {
		t.Fatal("ApprovalService.HasClient = nil, want product callback")
	}
	if !svc.HasClient() {
		t.Fatal("ApprovalService.HasClient() = false, want true")
	}
	if !hub.hasClientCalled {
		t.Fatal("HasClient was not called")
	}
}

func TestRequestSigningApprovalDisconnectCleansPendingRequest(t *testing.T) {
	signer := &Signer{}

	ir := productruntime.New(productruntime.Config{
		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})
	signer.runtime = ir
	signerstartup.WireApprovalCoordinator(ir, signer.productBuildHooks())
	signer.ipcServer = newIPCServerWithActiveConn(&hubStubConn{})

	done := make(chan struct{})
	var approved bool
	var err error
	go func() {
		defer close(done)
		approved, err = ir.RequestSigningApproval("req-disconnect", "ADDR", "SENDER", "desc", 1, 2, nil, time.Second)
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

	ir := server.productRuntime()
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
	hasClientCalled bool
	signCalled      bool
	cancelCalled    bool
	tokenCalled     bool
	lockedCalled    bool
	keysCalled      bool
	statusCalled    bool
}

func (h *recordingAdminHub) reset() {
	*h = recordingAdminHub{}
}

func (h *recordingAdminHub) HasClient() bool {
	h.hasClientCalled = true
	return true
}

func (h *recordingAdminHub) SendSignRequest(_ *signerapproval.SignRequest) bool {
	h.signCalled = true
	return false
}

func (h *recordingAdminHub) SendSignRequestCanceled(_ *signerapproval.SignRequestCanceled) bool {
	h.cancelCalled = true
	return false
}

func (h *recordingAdminHub) SendTokenProvisioningRequest(_ *signerapproval.TokenProvisioningRequest) bool {
	h.tokenCalled = true
	return false
}

func (h *recordingAdminHub) NotifyLocked(_ adminproto.SignerLockedNotification) {
	h.lockedCalled = true
}

func (h *recordingAdminHub) NotifyKeysChanged(_ adminproto.KeysChangedNotification) {
	h.keysCalled = true
}

func (h *recordingAdminHub) NotifyStatus(_ string, _ int) {
	h.statusCalled = true
}
