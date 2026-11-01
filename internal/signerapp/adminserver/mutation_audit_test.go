// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"errors"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
)

// mutationAudit records the mutation audit calls a session makes, in order,
// with the actor each one was given. intentErr fails every intent.
type mutationAudit struct {
	intentErr error
	events    []string
	actors    []string
	results   []any
}

func (a *mutationAudit) LogAuthorizationDenied(SessionContext, auth.Action, auth.Resource, string) {}

func (a *mutationAudit) note(event string, ctx SessionContext) {
	a.events = append(a.events, event)
	a.actors = append(a.actors, ctx.AdminPrincipal.ID)
}

func (a *mutationAudit) LogPolicyApplyIntentDurableContext(ctx SessionContext, id string, req adminproto.ApplyPolicyRequest) error {
	if a.intentErr != nil {
		return a.intentErr
	}
	a.note("policy-intent:"+id, ctx)
	return nil
}

func (a *mutationAudit) LogPolicyApplyResultContext(ctx SessionContext, id string, result adminproto.ApplyPolicyResult) {
	a.note("policy-result:"+id, ctx)
	a.results = append(a.results, result)
}

func (a *mutationAudit) LogASASetUpdateIntentDurableContext(ctx SessionContext, id, action, network, genesis string, assetID uint64) error {
	if a.intentErr != nil {
		return a.intentErr
	}
	a.note("asa-intent:"+action+":"+id, ctx)
	return nil
}

func (a *mutationAudit) LogASASetAddResultContext(ctx SessionContext, id string, req adminproto.AddASARequest, result adminproto.AddASAResult) {
	a.note("asa-result:add:"+id, ctx)
	a.results = append(a.results, result)
}

func (a *mutationAudit) LogASASetRemoveResultContext(ctx SessionContext, id string, req adminproto.RemoveASARequest, result adminproto.RemoveASAResult) {
	a.note("asa-result:remove:"+id, ctx)
	a.results = append(a.results, result)
}

// orderedServices records when the service ran relative to the audit calls.
type orderedServices struct {
	*stubServices
	audit *mutationAudit
}

func (o orderedServices) ApplyPolicy(req adminproto.ApplyPolicyRequest) adminproto.ApplyPolicyResult {
	o.audit.events = append(o.audit.events, "service")
	return o.stubServices.ApplyPolicy(req)
}

func TestPolicyAndASAChangesRecordIntentThenOneOutcome(t *testing.T) {
	audit := &mutationAudit{}
	svc := &stubServices{
		applyPolicyResult: adminproto.ApplyPolicyResult{Success: true, Changed: true, GenerationID: "gen-2"},
		addASAResult:      adminproto.AddASAResult{Code: "asa_duplicate", Error: "already confirmed"},
		removeASAResult:   adminproto.RemoveASAResult{Success: true, GenerationID: "gen-3"},
	}
	ordered := orderedServices{svc, audit}
	session, _, conn, _ := boundAuditedPolicySession(svc, audit)
	session.settingsServices = ordered

	session.HandleApplyPolicy(&protocol.ApplyPolicyMessage{
		BaseMessage: protocol.BaseMessage{ID: "apply-1", Type: protocol.MsgTypeApplyPolicy},
		Documents:   []protocol.PolicyDocumentWire{{Key: "default", Document: "{}"}},
	})
	session.HandleAddASA(&protocol.AddASAMessage{BaseMessage: protocol.BaseMessage{ID: "add-1", Type: protocol.MsgTypeAddASA}})
	session.HandleRemoveASA(&protocol.RemoveASAMessage{BaseMessage: protocol.BaseMessage{ID: "rm-1", Type: protocol.MsgTypeRemoveASA}, Network: "mainnet", AssetID: 9})

	want := []string{"policy-intent:apply-1", "service", "policy-result:apply-1", "asa-intent:add:add-1", "asa-result:add:add-1", "asa-intent:remove:rm-1", "asa-result:remove:rm-1"}
	if strings.Join(audit.events, " ") != strings.Join(want, " ") {
		t.Fatalf("audit order:\n got %v\nwant %v", audit.events, want)
	}
	for _, actor := range audit.actors {
		if actor != "admin-principal" {
			t.Fatalf("actor %q, want the session's principal", actor)
		}
	}
	if got := audit.results[1].(adminproto.AddASAResult); got.Code != "asa_duplicate" {
		t.Fatalf("a duplicate add was not recorded as its own failure: %+v", got)
	}
	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 3 || !msgs[0].Success || msgs[1].Success || msgs[1].Code != "asa_duplicate" || !msgs[2].Success {
		t.Fatalf("responses = %+v", msgs)
	}
}

// No audit log, or an intent that cannot be written, refuses every change
// before the service runs, with a code that says whether to restart or
// retry.
func TestPolicyAndASAChangesRefuseWithoutADurableIntent(t *testing.T) {
	for _, tt := range []struct {
		name  string
		audit AuthorizationAudit
		code  string
		hint  string
	}{
		{"no audit sink", nil, protocol.ResultCodeAuditUnavailable, "restart the daemon"},
		{"a sink without the probes", denialOnlyAudit{}, protocol.ResultCodeAuditUnavailable, "restart the daemon"},
		{"no logger", &mutationAudit{intentErr: ErrAuditUnavailable}, protocol.ResultCodeAuditUnavailable, "retrying the request alone cannot help"},
		{"a failed write", &mutationAudit{intentErr: errors.New("sync audit log: no space left on device")}, protocol.ResultCodeAuditWriteFailed, "no space left on device"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			svc := &stubServices{}
			session, _, conn, _ := boundAuditedPolicySession(svc, tt.audit)
			session.HandleApplyPolicy(&protocol.ApplyPolicyMessage{BaseMessage: protocol.BaseMessage{ID: "apply-1", Type: protocol.MsgTypeApplyPolicy}})
			session.HandleAddASA(&protocol.AddASAMessage{BaseMessage: protocol.BaseMessage{ID: "add-1", Type: protocol.MsgTypeAddASA}})
			session.HandleRemoveASA(&protocol.RemoveASAMessage{BaseMessage: protocol.BaseMessage{ID: "rm-1", Type: protocol.MsgTypeRemoveASA}})
			if svc.applyPolicyCalls+svc.addASACalls+svc.removeASACalls != 0 {
				t.Fatalf("a change ran without its intent: apply %d add %d remove %d", svc.applyPolicyCalls, svc.addASACalls, svc.removeASACalls)
			}
			msgs := decodeAdminProtoWrites(t, conn)
			if len(msgs) != 3 {
				t.Fatalf("responses = %+v", msgs)
			}
			for i, m := range msgs {
				if m.Success || m.Code != tt.code || !strings.Contains(m.Error, tt.hint) {
					t.Fatalf("response %d = %+v, want %s mentioning %q", i, m, tt.code, tt.hint)
				}
			}
			if !strings.Contains(msgs[0].Error, "apadmin policy rescue") || strings.Contains(msgs[1].Error, "rescue") {
				t.Fatalf("rescue advice: policy %q, asa %q", msgs[0].Error, msgs[1].Error)
			}
		})
	}
}

type denialOnlyAudit struct{}

func (denialOnlyAudit) LogAuthorizationDenied(SessionContext, auth.Action, auth.Resource, string) {}
