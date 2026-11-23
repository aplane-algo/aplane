// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/keyclass"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// TestSignerStateString verifies signerruntime.SignerState.String() returns correct values
func TestSignerStateString(t *testing.T) {
	tests := []struct {
		state    signerruntime.SignerState
		expected string
	}{
		{signerruntime.SignerStateLocked, "locked"},
		{signerruntime.SignerStateUnlocked, "unlocked"},
		{signerruntime.SignerStateRecovery, "recovery"},
		{signerruntime.SignerState(99), "unknown"}, // Invalid state
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.state.String()
			if result != tt.expected {
				t.Errorf("signerruntime.SignerState(%d).String() = %q, want %q", tt.state, result, tt.expected)
			}
		})
	}
}

func TestRegistryInitializesSignerRuntime(t *testing.T) {
	signer := &Signer{}

	ir := productruntime.New(productruntime.Config{})
	signer.runtime = ir
	signerstartup.WireApprovalCoordinator(ir, signer.productBuildHooks())

	if signer.productRuntime() == nil {
		t.Fatal("registry did not store product runtime")
	}

	if signer.getState() != signerruntime.SignerStateLocked {
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

	ir := productruntime.New(productruntime.Config{})
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
	if signer.getState() != signerruntime.SignerStateUnlocked {
		t.Errorf("getState() = %v, want %v", signer.getState(), signerruntime.SignerStateUnlocked)
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

	ir := productruntime.New(productruntime.Config{})
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

	ir := productruntime.New(productruntime.Config{})
	signer.runtime = ir
	signerstartup.WireApprovalCoordinator(ir, signer.productBuildHooks())
	signer.ipcServer = newIPCServerWithActiveConn(&hubStubConn{})
	signer.hub = signer.ipcServer

	approved, err := approvalOutcome(ir.RequestSigningApprovalPrompt(context.Background(), signerapproval.Prompt{RequestID: "req-timeout", Address: "ADDR", TxnSender: "SENDER", Description: "desc", FirstValid: 1, LastValid: 2}, 10*time.Millisecond))
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

	ir := productruntime.New(productruntime.Config{})
	signer.runtime = ir
	signerstartup.WireApprovalCoordinator(ir, signer.productBuildHooks())

	approved, err := approvalOutcome(ir.RequestSigningApprovalPrompt(context.Background(), signerapproval.Prompt{RequestID: "req-sign", Address: "ADDR", TxnSender: "SENDER", Description: "desc", FirstValid: 1, LastValid: 2}, time.Second))
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

}

// A reload that publishes on an unlocked signer tells the admin session its
// key count, through the hooks the process root wires into the runtime.
func TestAReloadNotifiesTheProductAdminHub(t *testing.T) {
	server := characterizedSigner(t)
	hub := &recordingAdminHub{}
	server.hub = hub
	if err := server.adminServices().withStoreMutation(func() error {
		_, err := server.productRuntime().Reload()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !hub.keysCalled {
		t.Fatal("the reload did not tell the admin session its key count")
	}
}

// A reload whose build finds a role conflict, here a source token file on a
// signer node, fails the node closed through the hooks the process root wires
// into the runtime, and enters recovery.
func TestAReloadFailsTheNodeClosedOnARoleConflict(t *testing.T) {
	server := characterizedSigner(t)
	server.nodeFailState = &productruntime.NodeFailState{}
	signerstartup.WireReloadFunc(server.productRuntime(), testProductBuildOptions(server), server.productBuildHooks())
	writeTokenEntry(t, server, storepaths.SourceTokensDefaultSelector+storepaths.SourceTokenFileExtension)
	err := server.adminServices().withStoreMutation(func() error {
		_, err := server.productRuntime().Reload()
		return err
	})
	if !errors.Is(err, keyclass.ErrNodeRoleConflict) || !server.productRuntime().IsRecovery() {
		t.Fatalf("Reload() = %v, state %v; want a role conflict and recovery", err, server.productRuntime().GetState())
	}
	if closeErr := server.nodeFailState.Err(); !errors.Is(closeErr, productruntime.ErrNodeFailClosed) {
		t.Fatalf("node failure = %v, want ErrNodeFailClosed", closeErr)
	}
}

func TestApprovalServiceChecksProductAdminClient(t *testing.T) {
	hub := &recordingAdminHub{}
	signer := &Signer{
		hub: hub,
	}
	ir := productruntime.New(productruntime.Config{})
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

	ir := productruntime.New(productruntime.Config{})
	signer.runtime = ir
	signerstartup.WireApprovalCoordinator(ir, signer.productBuildHooks())
	signer.ipcServer = newIPCServerWithActiveConn(&hubStubConn{})
	signer.hub = signer.ipcServer

	done := make(chan struct{})
	var approved bool
	var err error
	go func() {
		defer close(done)
		approved, err = approvalOutcome(ir.RequestSigningApprovalPrompt(context.Background(), signerapproval.Prompt{RequestID: "req-disconnect", Address: "ADDR", TxnSender: "SENDER", Description: "desc", FirstValid: 1, LastValid: 2}, time.Second))
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

	signer.failAllPendingApprovals(signerapproval.SignRequestCancelReasonApproverDisconnected)
	<-done

	// A disconnect withdraws the prompt: nobody rejected it.
	if !errors.Is(err, signerapproval.ErrApproverGone) {
		t.Fatalf("error after disconnect cleanup = %v, want ErrApproverGone", err)
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

	outcome, err := unlockForTest(server, []byte("wrong-passphrase"))
	if outcome.KeyCount != 0 {
		t.Fatalf("keyCount = %d, want 0", outcome.KeyCount)
	}
	if err == nil || err.Error() != "invalid passphrase" {
		t.Fatalf("error = %v, want invalid passphrase", err)
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
	statusWarnings    []string
	hasClientCalled   bool
	signCalled        bool
	cancelCalled      bool
	tokenCalled       bool
	lockedCalled      bool
	keysCalled        bool
	enrollmentChanges []adminproto.EnrollmentChangedNotification
	statusCalled      bool
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

func (h *recordingAdminHub) SendClientEnrollmentRequest(_ *signerapproval.ClientEnrollmentRequest) bool {
	h.tokenCalled = true
	return false
}

func (h *recordingAdminHub) NotifyLocked(_ adminproto.SignerLockedNotification) {
	h.lockedCalled = true
}

func (h *recordingAdminHub) NotifyKeysChanged(_ adminproto.KeysChangedNotification) {
	h.keysCalled = true
}

func (h *recordingAdminHub) NotifyEnrollmentChanged(n adminproto.EnrollmentChangedNotification) {
	h.enrollmentChanges = append(h.enrollmentChanges, n)
}

func (h *recordingAdminHub) NotifyStatus(_ string, _ int, warnings []string) {
	h.statusWarnings = append([]string(nil), warnings...)
	h.statusCalled = true
}

// approvalOutcome is a prompt's answer as approved or not.
func approvalOutcome(response signerapproval.SignResponse, err error) (bool, error) {
	if err != nil {
		return false, err
	}
	return response.Approved, nil
}
