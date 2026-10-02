// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"context"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

type recordingAuthorizer struct {
	err   error
	calls int
	got   struct {
		identityID string
		action     auth.Action
		resource   auth.Resource
	}
}

func (a *recordingAuthorizer) Authorize(ctx context.Context, identity *auth.Identity, action auth.Action, resource auth.Resource) error {
	_ = ctx
	a.calls++
	if identity != nil {
		a.got.identityID = identity.ID
	}
	a.got.action = action
	a.got.resource = resource
	return a.err
}

type recordingAuthorizationAudit struct {
	calls    int
	ctx      SessionContext
	action   auth.Action
	resource auth.Resource
	reason   string
}

func (a *recordingAuthorizationAudit) LogAuthorizationDenied(ctx SessionContext, action auth.Action, resource auth.Resource, reason string) {
	a.calls++
	a.ctx = ctx
	a.action = action
	a.resource = resource
	a.reason = reason
}

func TestSessionAuthorizationDenialStopsAdminOperation(t *testing.T) {
	ir := productruntime.New(productruntime.Config{

		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	svc := &stubServices{}
	authorizer := &recordingAuthorizer{err: auth.ErrForbidden}
	audit := &recordingAuthorizationAudit{}
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{
		Product:    svc,
		Settings:   svc,
		Keys:       svc,
		Templates:  svc,
		Authorizer: authorizer,
		Audit:      audit,
	})
	session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)

	session.HandleListKeyTypes("req-authz")

	if svc.listKeyTypesCalls != 0 {
		t.Fatalf("ListKeyTypes calls = %d, want 0", svc.listKeyTypesCalls)
	}
	if authorizer.got.identityID != "admin-principal" {
		t.Fatalf("authorizer identityID = %q, want admin-principal", authorizer.got.identityID)
	}
	if authorizer.got.action != auth.ActionKeyTypesView {
		t.Fatalf("authorizer action = %q, want %q", authorizer.got.action, auth.ActionKeyTypesView)
	}
	if authorizer.got.resource.Type != "keytypes" {
		t.Fatalf("authorizer resource = %+v, want keytypes", authorizer.got.resource)
	}

	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 1 {
		t.Fatalf("write count = %d, want 1", len(msgs))
	}
	if msgs[0].Type != protocol.MsgTypeError || msgs[0].ID != "req-authz" || msgs[0].Code != protocol.ErrCodeAuthorizationDenied {
		t.Fatalf("response = %+v, want authorization_denied error", msgs[0])
	}
	if audit.calls != 1 {
		t.Fatalf("audit calls = %d, want 1", audit.calls)
	}
	if audit.ctx.AdminPrincipal.ID != "admin-principal" {
		t.Fatalf("audit context = %+v, want admin-principal", audit.ctx)
	}
	if audit.action != auth.ActionKeyTypesView || audit.resource.Type != "keytypes" {
		t.Fatalf("audit decision = action %q resource %+v, want keytypes", audit.action, audit.resource)
	}
	if audit.reason != auth.ErrForbidden.Error() {
		t.Fatalf("audit reason = %q, want %q", audit.reason, auth.ErrForbidden.Error())
	}
}

func TestSessionAuthorizationWithoutBoundRuntimeFailsClosed(t *testing.T) {
	authorizer := &recordingAuthorizer{}
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{Authorizer: authorizer})

	if session.authorize("req-missing", auth.ActionKeysView, auth.Resource{Type: "keys"}) {
		t.Fatal("authorize() = true, want false")
	}
	if authorizer.calls != 0 {
		t.Fatalf("authorizer calls = %d, want 0", authorizer.calls)
	}

	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 1 {
		t.Fatalf("write count = %d, want 1", len(msgs))
	}
	if msgs[0].Type != protocol.MsgTypeError || msgs[0].Code != protocol.ErrCodeNoRuntimeBound {
		t.Fatalf("response = %+v, want no_runtime_bound error", msgs[0])
	}
}

func TestAdminHandlersWithoutBoundRuntimeReturnProtocolError(t *testing.T) {
	tests := []struct {
		name   string
		handle func(*Session)
	}{
		{
			name: "revoke token",
			handle: func(session *Session) {
				session.HandleRevokeToken(&protocol.RevokeTokenMessage{BaseMessage: protocol.BaseMessage{ID: "request-1"}})
			},
		},
		{
			name: "get admin settings",
			handle: func(session *Session) {
				session.HandleGetAdminSettings("request-1")
			},
		},
		{
			name: "update admin setting",
			handle: func(session *Session) {
				session.HandleUpdateAdminSetting(&protocol.UpdateAdminSettingMessage{BaseMessage: protocol.BaseMessage{ID: "request-1"}})
			},
		},
		{
			name: "get policy",
			handle: func(session *Session) {
				session.HandleGetPolicy(&protocol.GetPolicyMessage{BaseMessage: protocol.BaseMessage{ID: "request-1"}})
			},
		},
		{
			name: "check policy",
			handle: func(session *Session) {
				session.HandleCheckPolicy(&protocol.CheckPolicyMessage{BaseMessage: protocol.BaseMessage{ID: "request-1"}})
			},
		},
		{
			name: "apply policy",
			handle: func(session *Session) {
				session.HandleApplyPolicy(&protocol.ApplyPolicyMessage{BaseMessage: protocol.BaseMessage{ID: "request-1"}})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := &queueConn{}
			test.handle(NewSession(conn, SessionDeps{}))

			msgs := decodeAdminProtoWrites(t, conn)
			if len(msgs) != 1 {
				t.Fatalf("write count = %d, want 1", len(msgs))
			}
			if msgs[0].Type != protocol.MsgTypeError || msgs[0].ID != "request-1" || msgs[0].Code != protocol.ErrCodeNoRuntimeBound {
				t.Fatalf("response = %+v, want no_runtime_bound error for request-1", msgs[0])
			}
		})
	}
}

// boundPolicySession binds a session over svc with a recording authorizer.
func boundPolicySession(svc *stubServices) (*Session, *recordingAuthorizer, *queueConn) {
	ir := productruntime.New(productruntime.Config{Authenticator: auth.NewTokenAuthenticator("token")})
	authorizer := &recordingAuthorizer{}
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{Product: svc, Settings: svc, Authorizer: authorizer})
	session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)
	return session, authorizer, conn
}

func TestHandleGetPolicyAuthorizesPolicyView(t *testing.T) {
	svc := &stubServices{getPolicyResult: adminproto.PolicyView{Success: true, NodeRole: "cosigner", PolicySetSHA256: "set1"}}
	session, authorizer, conn := boundPolicySession(svc)

	session.HandleGetPolicy(&protocol.GetPolicyMessage{BaseMessage: protocol.BaseMessage{ID: "policy-1", Type: protocol.MsgTypeGetPolicy}})

	if svc.getPolicyCalls != 1 || authorizer.got.action != auth.ActionPolicyView || authorizer.got.resource.Type != "policy" {
		t.Fatalf("calls = %d, authorization = %+v", svc.getPolicyCalls, authorizer.got)
	}
	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 1 || msgs[0].Type != protocol.MsgTypePolicy || msgs[0].ID != "policy-1" ||
		!msgs[0].Success || msgs[0].PolicySetSHA256 != "set1" {
		t.Fatalf("responses = %+v", msgs)
	}
}

func TestHandleCheckPolicyAuthorizesPolicyView(t *testing.T) {
	svc := &stubServices{checkPolicyResult: adminproto.CheckPolicyResult{Success: true, Valid: true}}
	session, authorizer, conn := boundPolicySession(svc)

	session.HandleCheckPolicy(&protocol.CheckPolicyMessage{
		BaseMessage: protocol.BaseMessage{ID: "check-1", Type: protocol.MsgTypeCheckPolicy},
		Documents:   []protocol.PolicyDocumentWire{{Key: "K1", Document: "{}", SHA256: "ignored"}},
		Remove:      []string{"K2"},
	})

	if svc.checkPolicyCalls != 1 || authorizer.got.action != auth.ActionPolicyView {
		t.Fatalf("calls = %d, authorization = %+v", svc.checkPolicyCalls, authorizer.got)
	}
	if got := svc.lastCheckPolicy; len(got.Documents) != 1 || got.Documents[0] != (adminproto.PolicyDocument{Key: "K1", Document: "{}"}) ||
		len(got.Remove) != 1 || got.Remove[0] != "K2" {
		t.Fatalf("CheckPolicy request = %+v", got)
	}
	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 1 || msgs[0].Type != protocol.MsgTypeCheckPolicyResult || !msgs[0].Valid {
		t.Fatalf("responses = %+v", msgs)
	}
}

func TestHandleApplyPolicyAuthorizesPolicyUpdate(t *testing.T) {
	svc := &stubServices{applyPolicyResult: adminproto.ApplyPolicyResult{Success: true, Policy: &adminproto.PolicyView{Success: true, PolicySetSHA256: "set2"}}}
	session, authorizer, conn := boundPolicySession(svc)

	session.HandleApplyPolicy(&protocol.ApplyPolicyMessage{
		BaseMessage:             protocol.BaseMessage{ID: "apply-1", Type: protocol.MsgTypeApplyPolicy},
		Documents:               []protocol.PolicyDocumentWire{{Document: "{}"}},
		ExpectedPolicySetSHA256: "set1",
	})

	if svc.applyPolicyCalls != 1 || authorizer.got.action != auth.ActionPolicyUpdate || authorizer.got.resource.Type != "policy" {
		t.Fatalf("calls = %d, authorization = %+v", svc.applyPolicyCalls, authorizer.got)
	}
	if got := svc.lastApplyPolicy; got.ExpectedPolicySetSHA256 != "set1" || len(got.Documents) != 1 || got.Documents[0].Document != "{}" {
		t.Fatalf("ApplyPolicy request = %+v", got)
	}
	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 1 || msgs[0].Type != protocol.MsgTypeApplyPolicyResult || msgs[0].ID != "apply-1" || !msgs[0].Success {
		t.Fatalf("responses = %+v", msgs)
	}
}
