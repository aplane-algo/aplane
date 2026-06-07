// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminproto

import (
	"context"
	"testing"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
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
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	svc := &stubServices{}
	authorizer := &recordingAuthorizer{err: auth.ErrForbidden}
	audit := &recordingAuthorizationAudit{}
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{
		Identity:   svc,
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
	if authorizer.got.resource.Type != "keytypes" || authorizer.got.resource.IdentityID != auth.DefaultIdentityID {
		t.Fatalf("authorizer resource = %+v, want keytypes/default", authorizer.got.resource)
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
	if audit.ctx.TargetIdentityID != auth.DefaultIdentityID || audit.ctx.AdminPrincipal.ID != "admin-principal" {
		t.Fatalf("audit context = %+v, want target default and admin-principal", audit.ctx)
	}
	if audit.action != auth.ActionKeyTypesView || audit.resource.Type != "keytypes" || audit.resource.IdentityID != auth.DefaultIdentityID {
		t.Fatalf("audit decision = action %q resource %+v, want keytypes/default", audit.action, audit.resource)
	}
	if audit.reason != auth.ErrForbidden.Error() {
		t.Fatalf("audit reason = %q, want %q", audit.reason, auth.ErrForbidden.Error())
	}
}

func TestSessionAuthorizationMissingIdentityFailsClosed(t *testing.T) {
	authorizer := &recordingAuthorizer{}
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{Authorizer: authorizer})

	if session.authorize("req-missing", auth.ActionKeysView, auth.Resource{Type: "keys", IdentityID: auth.DefaultIdentityID}) {
		t.Fatal("authorize() = true, want false")
	}
	if authorizer.calls != 0 {
		t.Fatalf("authorizer calls = %d, want 0", authorizer.calls)
	}

	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 1 {
		t.Fatalf("write count = %d, want 1", len(msgs))
	}
	if msgs[0].Type != protocol.MsgTypeError || msgs[0].Code != protocol.ErrCodeNoIdentityBound {
		t.Fatalf("response = %+v, want no_identity_bound error", msgs[0])
	}
}

func TestHandleGetPolicySnapshotAuthorizesPolicyView(t *testing.T) {
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	svc := &stubServices{
		policySnapshotResult: PolicySnapshot{
			Success:      true,
			Target:       PolicyTargetSentry,
			IdentityID:   auth.DefaultIdentityID,
			PolicyYAML:   "reject_foreign_rekey: true\n",
			PolicySHA256: "abc123",
			Canonical:    true,
		},
	}
	authorizer := &recordingAuthorizer{}
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{
		Identity:   svc,
		Settings:   svc,
		Authorizer: authorizer,
	})
	session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)

	session.HandleGetPolicySnapshot(&protocol.GetPolicySnapshotMessage{
		BaseMessage: protocol.BaseMessage{ID: "snapshot-1", Type: protocol.MsgTypeGetPolicySnapshot},
		Target:      "sentry",
	})

	if svc.policySnapshotCalls != 1 {
		t.Fatalf("BuildPolicySnapshot calls = %d, want 1", svc.policySnapshotCalls)
	}
	if svc.lastPolicySnapshot != PolicyTargetSentry {
		t.Fatalf("BuildPolicySnapshot target = %q, want sentry", svc.lastPolicySnapshot)
	}
	if authorizer.got.action != auth.ActionPolicyView {
		t.Fatalf("authorizer action = %q, want %q", authorizer.got.action, auth.ActionPolicyView)
	}
	if authorizer.got.resource.Type != "policy" || authorizer.got.resource.IdentityID != auth.DefaultIdentityID {
		t.Fatalf("authorizer resource = %+v, want policy/default", authorizer.got.resource)
	}

	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 1 {
		t.Fatalf("write count = %d, want 1", len(msgs))
	}
	if msgs[0].Type != protocol.MsgTypePolicySnapshot || msgs[0].ID != "snapshot-1" {
		t.Fatalf("response = %+v, want policy_snapshot snapshot-1", msgs[0])
	}
	if !msgs[0].Success || msgs[0].Target != "sentry" || msgs[0].PolicyYAML != "reject_foreign_rekey: true\n" || !msgs[0].Canonical {
		t.Fatalf("policy snapshot response = %+v, want successful canonical YAML", msgs[0])
	}
}

func TestHandleReplacePolicyAuthorizesPolicyUpdate(t *testing.T) {
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	svc := &stubServices{
		replacePolicyResult: PolicySnapshot{
			Success:    true,
			IdentityID: auth.DefaultIdentityID,
			PolicyYAML: "reject_foreign_rekey: false\n",
			Canonical:  true,
		},
	}
	authorizer := &recordingAuthorizer{}
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{
		Identity:   svc,
		Settings:   svc,
		Authorizer: authorizer,
	})
	session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)

	session.HandleReplacePolicy(&protocol.ReplacePolicyMessage{
		BaseMessage:           protocol.BaseMessage{ID: "replace-1", Type: protocol.MsgTypeReplacePolicy},
		Target:                "sentry",
		PolicyYAML:            "reject_foreign_rekey: false\n",
		ExpectedCurrentSHA256: "abc123",
	})

	if svc.replacePolicyCalls != 1 {
		t.Fatalf("ReplacePolicy calls = %d, want 1", svc.replacePolicyCalls)
	}
	if svc.lastReplacePolicy.PolicyYAML != "reject_foreign_rekey: false\n" ||
		svc.lastReplacePolicy.ExpectedCurrentSHA256 != "abc123" ||
		svc.lastReplacePolicy.Target != PolicyTargetSentry {
		t.Fatalf("ReplacePolicy request = %+v, want YAML and expected SHA", svc.lastReplacePolicy)
	}
	if authorizer.got.action != auth.ActionPolicyUpdate {
		t.Fatalf("authorizer action = %q, want %q", authorizer.got.action, auth.ActionPolicyUpdate)
	}
	if authorizer.got.resource.Type != "policy" || authorizer.got.resource.IdentityID != auth.DefaultIdentityID {
		t.Fatalf("authorizer resource = %+v, want policy/default", authorizer.got.resource)
	}

	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 1 {
		t.Fatalf("write count = %d, want 1", len(msgs))
	}
	if msgs[0].Type != protocol.MsgTypeReplacePolicyResult || msgs[0].ID != "replace-1" {
		t.Fatalf("response = %+v, want replace_policy_result replace-1", msgs[0])
	}
	if !msgs[0].Success || msgs[0].PolicyYAML != "reject_foreign_rekey: false\n" || !msgs[0].Canonical {
		t.Fatalf("replace policy response = %+v, want successful canonical YAML", msgs[0])
	}
}

func TestHandleValidatePolicyAuthorizesPolicyView(t *testing.T) {
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	svc := &stubServices{
		validatePolicyResult: ValidatePolicyResult{
			Success:    true,
			Target:     PolicyTargetSentry,
			IdentityID: auth.DefaultIdentityID,
		},
	}
	authorizer := &recordingAuthorizer{}
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{
		Identity:   svc,
		Settings:   svc,
		Authorizer: authorizer,
	})
	session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)

	session.HandleValidatePolicy(&protocol.ValidatePolicyMessage{
		BaseMessage: protocol.BaseMessage{ID: "validate-1", Type: protocol.MsgTypeValidatePolicy},
		Target:      "sentry",
		PolicyYAML:  "sentry:\n  transfer_policy:\n    schema_version: 1\n",
	})

	if svc.validatePolicyCalls != 1 {
		t.Fatalf("ValidatePolicy calls = %d, want 1", svc.validatePolicyCalls)
	}
	if svc.lastValidatePolicy.Target != PolicyTargetSentry ||
		svc.lastValidatePolicy.PolicyYAML != "sentry:\n  transfer_policy:\n    schema_version: 1\n" {
		t.Fatalf("ValidatePolicy request = %+v, want sentry YAML", svc.lastValidatePolicy)
	}
	if authorizer.got.action != auth.ActionPolicyView {
		t.Fatalf("authorizer action = %q, want %q", authorizer.got.action, auth.ActionPolicyView)
	}
	if authorizer.got.resource.Type != "policy" || authorizer.got.resource.IdentityID != auth.DefaultIdentityID {
		t.Fatalf("authorizer resource = %+v, want policy/default", authorizer.got.resource)
	}

	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 1 {
		t.Fatalf("write count = %d, want 1", len(msgs))
	}
	if msgs[0].Type != protocol.MsgTypeValidatePolicyResult || msgs[0].ID != "validate-1" {
		t.Fatalf("response = %+v, want validate_policy_result validate-1", msgs[0])
	}
	if !msgs[0].Success || msgs[0].Target != "sentry" {
		t.Fatalf("validate policy response = %+v, want successful sentry result", msgs[0])
	}
}
