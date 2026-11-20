// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

type recordingIdentityLockAudit struct {
	recordingAuthorizationAudit
	lockCalls int
	lockCtx   SessionContext
	reason    string
}

func (a *recordingIdentityLockAudit) LogIdentityLockedContext(ctx SessionContext, reason string) {
	a.lockCalls++
	a.lockCtx = ctx
	a.reason = reason
}

func TestHandleLockIdentityAuthorizesLocksAndAudits(t *testing.T) {
	ir := productruntime.New(productruntime.Config{})
	ir.SetUnlocked()

	conn := &queueConn{}
	authorizer := &recordingAuthorizer{}
	audit := &recordingIdentityLockAudit{}
	session := NewSession(conn, SessionDeps{
		Authorizer: authorizer,
		Audit:      audit,
	}, OriginLocal)
	session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)

	session.HandleLockIdentity(&protocol.LockIdentityMessage{
		BaseMessage: protocol.BaseMessage{ID: "lock-1"},
		Reason:      "apadmin manual lock",
	})

	if ir.IsUnlocked() {
		t.Fatal("identity is still unlocked after HandleLockIdentity")
	}
	if authorizer.calls != 1 {
		t.Fatalf("authorizer calls = %d, want 1", authorizer.calls)
	}
	if authorizer.got.action != auth.ActionIdentityLock {
		t.Fatalf("authorizer action = %q, want %q", authorizer.got.action, auth.ActionIdentityLock)
	}
	if authorizer.got.resource.Type != "identity" {
		t.Fatalf("authorizer resource = %+v, want identity", authorizer.got.resource)
	}
	if audit.lockCalls != 1 {
		t.Fatalf("audit lock calls = %d, want 1", audit.lockCalls)
	}
	if audit.lockCtx.AdminPrincipal.ID != "admin-principal" {
		t.Fatalf("audit context = %+v, want admin-principal", audit.lockCtx)
	}
	if audit.reason != "apadmin manual lock" {
		t.Fatalf("audit reason = %q", audit.reason)
	}

	var result protocol.LockIdentityResultMessage
	if len(conn.writes) != 1 {
		t.Fatalf("write count = %d, want 1", len(conn.writes))
	}
	if err := json.Unmarshal(conn.writes[0], &result); err != nil {
		t.Fatalf("decode lock result: %v", err)
	}
	if result.Type != protocol.MsgTypeLockIdentityResult || result.ID != "lock-1" || !result.Success {
		t.Fatalf("lock result = %+v, want successful lock_identity_result", result)
	}
}

// A lock withdraws the approval waiting on the operator's screen as having
// outlived its session, not as an operator rejection.
func TestHandleLockIdentityWithdrawsPendingApprovals(t *testing.T) {
	ir := productruntime.New(productruntime.Config{})
	ir.SetUnlocked()

	delivered := make(chan struct{}, 1)
	ir.SetApprovalCoordinator(signerapproval.New(
		func() bool { return true },
		func(req *signerapproval.SignRequest) bool {
			delivered <- struct{}{}
			return true
		},
		nil,
	))

	// Every production sign request registers itself (BeginSigningRequest)
	// before it asks for approval.
	ctx, finish := ir.BeginSigningRequest(context.Background(), "lock-pending")
	defer finish()
	result := make(chan error, 1)
	go func() {
		_, err := ir.RequestSigningApprovalPrompt(ctx, signerapproval.Prompt{RequestID: "lock-pending", Address: "A", TxnSender: "A", Description: "desc"}, time.Minute)
		if !errors.Is(err, signerapproval.ErrSessionEnded) {
			result <- fmt.Errorf("approval error = %v, want the session-ended withdrawal", err)
			return
		}
		result <- nil
	}()

	select {
	case <-delivered:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for approval delivery")
	}

	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{}, OriginLocal)
	session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)
	session.HandleLockIdentity(&protocol.LockIdentityMessage{
		BaseMessage: protocol.BaseMessage{ID: "lock-1"},
		Reason:      "apadmin manual lock",
	})

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("approval result error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending approval did not finish after lock")
	}
}

func TestHandleLockIdentityRejectsUnauthorizedRequest(t *testing.T) {
	ir := productruntime.New(productruntime.Config{})
	ir.SetUnlocked()

	conn := &queueConn{}
	authorizer := &recordingAuthorizer{err: auth.ErrForbidden}
	audit := &recordingIdentityLockAudit{}
	session := NewSession(conn, SessionDeps{
		Authorizer: authorizer,
		Audit:      audit,
	}, OriginLocal)
	session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)

	session.HandleLockIdentity(&protocol.LockIdentityMessage{
		BaseMessage: protocol.BaseMessage{ID: "lock-denied"},
		Reason:      "apadmin manual lock",
	})

	if !ir.IsUnlocked() {
		t.Fatal("identity locked after unauthorized HandleLockIdentity")
	}
	if authorizer.calls != 1 {
		t.Fatalf("authorizer calls = %d, want 1", authorizer.calls)
	}
	if audit.calls != 1 {
		t.Fatalf("authorization audit calls = %d, want 1", audit.calls)
	}
	if audit.lockCalls != 0 {
		t.Fatalf("identity lock audit calls = %d, want 0", audit.lockCalls)
	}

	var result protocol.LockIdentityResultMessage
	if len(conn.writes) != 1 {
		t.Fatalf("write count = %d, want 1", len(conn.writes))
	}
	if err := json.Unmarshal(conn.writes[0], &result); err != nil {
		t.Fatalf("decode lock result: %v", err)
	}
	if result.Type != protocol.MsgTypeLockIdentityResult || result.ID != "lock-denied" || result.Success {
		t.Fatalf("lock result = %+v, want unsuccessful lock_identity_result", result)
	}
	if result.Code != protocol.ErrCodeAuthorizationDenied {
		t.Fatalf("lock result code = %q, want %q", result.Code, protocol.ErrCodeAuthorizationDenied)
	}
}

// A session bound without an identity is denied by an authorizer: both the
// generic gate and the lock request answer authorization_denied and audit the
// denial, and neither reaches the authorizer or locks the runtime.
func TestAuthorizationWithoutIdentityRefuses(t *testing.T) {
	newSession := func() (*Session, *productruntime.Runtime, *recordingAuthorizer, *recordingIdentityLockAudit, *queueConn) {
		ir := productruntime.New(productruntime.Config{})
		ir.SetUnlocked()
		conn := &queueConn{}
		authorizer := &recordingAuthorizer{}
		audit := &recordingIdentityLockAudit{}
		session := NewSession(conn, SessionDeps{Authorizer: authorizer, Audit: audit}, OriginLocal)
		session.Bind(nil, ir)
		return session, ir, authorizer, audit, conn
	}
	const wantCode = protocol.ErrCodeAuthorizationDenied
	const wantAudits = 1

	session, _, authorizer, audit, conn := newSession()
	if session.authorize("req-1", auth.ActionKeysView, auth.Resource{Type: "keys"}) {
		t.Fatal("authorize() = true, want false")
	}
	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 1 || msgs[0].Type != protocol.MsgTypeError || msgs[0].ID != "req-1" || msgs[0].Code != wantCode {
		t.Fatalf("authorize() responses = %+v, want one %s error", msgs, wantCode)
	}
	if authorizer.calls != 0 || audit.calls != wantAudits {
		t.Fatalf("authorize(): authorizer calls = %d, audit calls = %d, want 0 and %d", authorizer.calls, audit.calls, wantAudits)
	}

	session, ir, authorizer, audit, conn := newSession()
	session.HandleLockIdentity(&protocol.LockIdentityMessage{BaseMessage: protocol.BaseMessage{ID: "lock-1"}})
	if !ir.IsUnlocked() || audit.lockCalls != 0 {
		t.Fatal("a lock request without an identity locked the runtime")
	}
	var result protocol.LockIdentityResultMessage
	if len(conn.writes) != 1 {
		t.Fatalf("lock write count = %d, want 1", len(conn.writes))
	}
	if err := json.Unmarshal(conn.writes[0], &result); err != nil {
		t.Fatalf("decode lock result: %v", err)
	}
	if result.Success || result.ID != "lock-1" || result.Code != wantCode {
		t.Fatalf("lock result = %+v, want %s", result, wantCode)
	}
	if authorizer.calls != 0 || audit.calls != wantAudits {
		t.Fatalf("lock: authorizer calls = %d, audit calls = %d, want 0 and %d", authorizer.calls, audit.calls, wantAudits)
	}
}

// A lock request on a session that has not authenticated, or is being
// displaced, is refused before authorization.
func TestHandleLockIdentityRefusesASessionThatIsNotAuthenticated(t *testing.T) {
	ir := productruntime.New(productruntime.Config{})
	ir.SetUnlocked()
	conn := &queueConn{}
	authorizer := &recordingAuthorizer{}
	session := NewSession(conn, SessionDeps{Authorizer: authorizer}, OriginLocal)

	session.HandleLockIdentity(&protocol.LockIdentityMessage{BaseMessage: protocol.BaseMessage{ID: "lock-1"}})

	var result protocol.LockIdentityResultMessage
	if len(conn.writes) != 1 {
		t.Fatalf("write count = %d, want 1", len(conn.writes))
	}
	if err := json.Unmarshal(conn.writes[0], &result); err != nil {
		t.Fatalf("decode lock result: %v", err)
	}
	if result.Success || result.Code != protocol.ErrCodeNoRuntimeBound || authorizer.calls != 0 || !ir.IsUnlocked() {
		t.Fatalf("lock result = %+v, authorizer calls = %d, want no_runtime_bound before authorization", result, authorizer.calls)
	}

	// A bound session that was displaced still holds its runtime.
	displacedConn := &queueConn{}
	displaced := NewSession(displacedConn, SessionDeps{Authorizer: authorizer}, OriginLocal)
	displaced.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)
	DisplaceSession(displaced)
	displaced.HandleLockIdentity(&protocol.LockIdentityMessage{BaseMessage: protocol.BaseMessage{ID: "lock-2"}})
	if len(displacedConn.writes) != 2 {
		t.Fatalf("displaced write count = %d, want the displaced notice and the lock result", len(displacedConn.writes))
	}
	if err := json.Unmarshal(displacedConn.writes[1], &result); err != nil {
		t.Fatalf("decode lock result: %v", err)
	}
	if result.Success || result.Code != protocol.ErrCodeNoRuntimeBound || authorizer.calls != 0 || !ir.IsUnlocked() {
		t.Fatalf("displaced lock result = %+v, authorizer calls = %d, want no_runtime_bound before authorization", result, authorizer.calls)
	}
}
