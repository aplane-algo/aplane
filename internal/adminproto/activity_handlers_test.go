// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminproto

import (
	"encoding/json"
	"testing"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
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
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	ir.SetUnlocked()

	conn := &queueConn{}
	authorizer := &recordingAuthorizer{}
	audit := &recordingIdentityLockAudit{}
	session := NewSession(conn, SessionDeps{
		Authorizer: authorizer,
		Audit:      audit,
	})
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
	if authorizer.got.resource.Type != "identity" || authorizer.got.resource.IdentityID != auth.DefaultIdentityID {
		t.Fatalf("authorizer resource = %+v, want identity/default", authorizer.got.resource)
	}
	if audit.lockCalls != 1 {
		t.Fatalf("audit lock calls = %d, want 1", audit.lockCalls)
	}
	if audit.lockCtx.TargetIdentityID != auth.DefaultIdentityID || audit.lockCtx.AdminPrincipal.ID != "admin-principal" {
		t.Fatalf("audit context = %+v, want target default and admin-principal", audit.lockCtx)
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

func TestHandleLockIdentityRejectsUnauthorizedRequest(t *testing.T) {
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	ir.SetUnlocked()

	conn := &queueConn{}
	authorizer := &recordingAuthorizer{err: auth.ErrForbidden}
	audit := &recordingIdentityLockAudit{}
	session := NewSession(conn, SessionDeps{
		Authorizer: authorizer,
		Audit:      audit,
	})
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
