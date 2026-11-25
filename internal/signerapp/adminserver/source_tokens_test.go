// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

const testSourceToken = "tok-secret-7f3a"

func (a *mutationAudit) LogSourceTokenChangeIntentDurableContext(ctx SessionContext, id, action, selector, source string) error {
	if a.intentErr != nil {
		return a.intentErr
	}
	a.note(fmt.Sprintf("token-intent:%s:%s:%s:%s", action, selector, source, id), ctx)
	return nil
}

func (a *mutationAudit) LogSourceTokenChangeResultContext(ctx SessionContext, id, action, selector, source string, result adminproto.SourceTokenChangeResult) {
	a.note(fmt.Sprintf("token-result:%s:%s:%s:%s", action, selector, source, id), ctx)
	a.results = append(a.results, result)
}

func boundSourceTokenSession(svc *stubServices, audit Audit) (*Session, *recordingAuthorizer, *queueConn) {
	ir := productruntime.New(productruntime.Config{})
	authorizer := &recordingAuthorizer{}
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{Product: svc, Keys: svc, Authorizer: authorizer, Audit: audit}, OriginLocal)
	session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)
	return session, authorizer, conn
}

func setTokenMessage(id string) *protocol.SourceTokenSetMessage {
	return &protocol.SourceTokenSetMessage{
		BaseMessage: protocol.BaseMessage{ID: id, Type: protocol.MsgTypeSourceTokenSet},
		Selector:    "default", Source: "screening", Token: protocol.NewSensitiveBytes(testSourceToken),
	}
}

func isZeroedToken(b []byte) bool { return len(b) > 0 && bytes.Equal(b, make([]byte, len(b))) }

// All three messages take a policy apply's authorization, policy.update, on
// the selector's tokens.
func TestSourceTokenMessagesAuthorizeAsPolicyApply(t *testing.T) {
	svc := &stubServices{sourceTokenResult: adminproto.SourceTokenChangeResult{Success: true}}
	session, authorizer, _ := boundSourceTokenSession(svc, &mutationAudit{})
	for _, run := range []struct {
		name     string
		selector string
		handle   func()
	}{
		{"set", "default", func() { session.HandleSetSourceToken(setTokenMessage("set-1")) }},
		{"remove", "KEY1", func() {
			session.HandleRemoveSourceToken(&protocol.SourceTokenRemoveMessage{
				BaseMessage: protocol.BaseMessage{ID: "rm-1", Type: protocol.MsgTypeSourceTokenRemove}, Selector: "KEY1", Source: "screening",
			})
		}},
		{"list", "KEY2", func() {
			session.HandleListSourceTokens(&protocol.SourceTokenListMessage{
				BaseMessage: protocol.BaseMessage{ID: "ls-1", Type: protocol.MsgTypeSourceTokenList}, Selector: "KEY2",
			})
		}},
	} {
		run.handle()
		if authorizer.got.action != auth.ActionPolicyUpdate || authorizer.got.resource != (auth.Resource{Type: "source_tokens", ID: run.selector}) {
			t.Fatalf("%s: authorization = %+v", run.name, authorizer.got)
		}
	}
	if got := strings.Join(svc.sourceTokenCalls, " "); got != "set remove list:KEY2" {
		t.Fatalf("service calls = %q", got)
	}
}

// A denied session reaches no service, and its token is zeroed all the same.
func TestSourceTokenSetDeniedZeroesTheToken(t *testing.T) {
	svc := &stubServices{}
	session, authorizer, conn := boundSourceTokenSession(svc, &mutationAudit{})
	authorizer.err = auth.ErrForbidden
	msg := setTokenMessage("set-denied")
	session.HandleSetSourceToken(msg)
	if len(svc.sourceTokenCalls) != 0 {
		t.Fatalf("a denied set reached the service: %v", svc.sourceTokenCalls)
	}
	if !isZeroedToken(msg.Token) {
		t.Fatal("a denied set left its token in the request")
	}
	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 1 || msgs[0].Type != protocol.MsgTypeError || msgs[0].Code != protocol.ErrCodeAuthorizationDenied {
		t.Fatalf("responses = %+v", msgs)
	}
}

// The service gets the token; the request's copy is zeroed after; neither the
// response nor the audit records carry it.
func TestSourceTokenSetPassesTheTokenOnceAndNeverEchoesIt(t *testing.T) {
	setAt := time.Date(2026, 11, 21, 1, 2, 3, 0, time.UTC)
	svc := &stubServices{sourceTokenResult: adminproto.SourceTokenChangeResult{
		Success: true, Selector: "default", Source: "screening",
		Tokens: []adminproto.SourceTokenInfo{{Source: "screening", SetAt: setAt, State: adminproto.SourceTokenInUse}},
	}}
	audit := &mutationAudit{}
	session, _, conn := boundSourceTokenSession(svc, audit)
	msg := setTokenMessage("set-1")
	session.HandleSetSourceToken(msg)

	if string(svc.lastSourceToken) != testSourceToken || svc.lastSourceTokenRequest.Selector != "default" || svc.lastSourceTokenRequest.Source != "screening" {
		t.Fatalf("the service got %q for %+v", svc.lastSourceToken, svc.lastSourceTokenRequest)
	}
	if !isZeroedToken(msg.Token) {
		t.Fatal("the request's token was not zeroed after the set")
	}
	if len(conn.writes) != 1 {
		t.Fatalf("writes = %d", len(conn.writes))
	}
	if bytes.Contains(conn.writes[0], []byte(testSourceToken)) {
		t.Fatalf("the response carries the token: %s", conn.writes[0])
	}
	var result protocol.SourceTokenChangeResultMessage
	if err := json.Unmarshal(conn.writes[0], &result); err != nil {
		t.Fatal(err)
	}
	if result.Type != protocol.MsgTypeSourceTokenSetResult || result.ID != "set-1" || !result.Success ||
		len(result.Tokens) != 1 || result.Tokens[0] != (protocol.SourceTokenInfo{Source: "screening", SetAt: "2026-11-21T01:02:03Z", State: "in_use"}) {
		t.Fatalf("set result = %+v", result)
	}
	for _, event := range audit.events {
		if strings.Contains(event, testSourceToken) {
			t.Fatalf("audit records the token: %s", event)
		}
	}
	if got := fmt.Sprintf("%+v", audit.results); strings.Contains(got, testSourceToken) {
		t.Fatalf("audit results carry the token: %s", got)
	}
}

func TestSourceTokenChangesRecordIntentThenOneOutcome(t *testing.T) {
	audit := &mutationAudit{}
	svc := &stubServices{sourceTokenResult: adminproto.SourceTokenChangeResult{Success: true}}
	session, _, conn := boundSourceTokenSession(svc, audit)
	session.HandleSetSourceToken(setTokenMessage("set-1"))
	svc.sourceTokenResult = adminproto.SourceTokenChangeResult{Code: protocol.ErrCodeKeyNotFound, Error: "no token is set for this source"}
	session.HandleRemoveSourceToken(&protocol.SourceTokenRemoveMessage{
		BaseMessage: protocol.BaseMessage{ID: "rm-1", Type: protocol.MsgTypeSourceTokenRemove}, Selector: "default", Source: "ops",
	})
	want := []string{
		"token-intent:set:default:screening:set-1", "token-result:set:default:screening:set-1",
		"token-intent:remove:default:ops:rm-1", "token-result:remove:default:ops:rm-1",
	}
	if strings.Join(audit.events, " ") != strings.Join(want, " ") {
		t.Fatalf("audit order:\n got %v\nwant %v", audit.events, want)
	}
	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 2 || msgs[0].Type != protocol.MsgTypeSourceTokenSetResult || !msgs[0].Success ||
		msgs[1].Type != protocol.MsgTypeSourceTokenRemoveResult || msgs[1].Success || msgs[1].Code != protocol.ErrCodeKeyNotFound {
		t.Fatalf("responses = %+v", msgs)
	}
}

// Without a durable intent no change runs, and the set's token is zeroed.
func TestSourceTokenChangesRefuseWithoutADurableIntent(t *testing.T) {
	for _, tt := range []struct {
		name  string
		audit Audit
		code  string
	}{
		{"no logger", &stubAudit{}, protocol.ResultCodeAuditUnavailable},
		{"a failed write", &mutationAudit{intentErr: errors.New("sync audit log: no space left on device")}, protocol.ResultCodeAuditWriteFailed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			svc := &stubServices{}
			session, _, conn := boundSourceTokenSession(svc, tt.audit)
			msg := setTokenMessage("set-1")
			session.HandleSetSourceToken(msg)
			session.HandleRemoveSourceToken(&protocol.SourceTokenRemoveMessage{
				BaseMessage: protocol.BaseMessage{ID: "rm-1", Type: protocol.MsgTypeSourceTokenRemove}, Selector: "default", Source: "screening",
			})
			if len(svc.sourceTokenCalls) != 0 {
				t.Fatalf("a change ran without its intent: %v", svc.sourceTokenCalls)
			}
			if !isZeroedToken(msg.Token) {
				t.Fatal("a refused set left its token in the request")
			}
			msgs := decodeAdminProtoWrites(t, conn)
			if len(msgs) != 2 {
				t.Fatalf("responses = %+v", msgs)
			}
			for i, m := range msgs {
				if m.Success || m.Code != tt.code || strings.Contains(m.Error, "rescue") {
					t.Fatalf("response %d = %+v, want %s without rescue advice", i, m, tt.code)
				}
			}
		})
	}
}

// The dispatch table routes the three messages, decoding the token as a
// sensitive value, and an auth_only session, which an approval-only client
// holds, is refused every one of them before any service runs.
func TestSourceTokenDispatchAndAuthOnlyRefusal(t *testing.T) {
	frames := []string{
		`{"kind":"request","type":"source_token_set","id":"set-1","selector":"default","source":"screening","token":"` + testSourceToken + `"}`,
		`{"kind":"request","type":"source_token_remove","id":"rm-1","selector":"default","source":"screening"}`,
		`{"kind":"request","type":"source_token_list","id":"ls-1","selector":"default"}`,
	}
	for _, messageType := range []string{protocol.MsgTypeSourceTokenSet, protocol.MsgTypeSourceTokenRemove, protocol.MsgTypeSourceTokenList} {
		if authOnlyDispatchTypes[messageType] {
			t.Errorf("%s is open to auth_only sessions", messageType)
		}
	}

	svc := &stubServices{sourceTokenResult: adminproto.SourceTokenChangeResult{Success: true}, listSourceTokensResult: adminproto.ListSourceTokensResult{Success: true}}
	session, _, conn := boundSourceTokenSession(svc, &mutationAudit{})
	session.authenticatedOnly = true
	for _, frame := range frames {
		session.Dispatch([]byte(frame))
	}
	if len(svc.sourceTokenCalls) != 0 {
		t.Fatalf("an auth_only session reached the service: %v", svc.sourceTokenCalls)
	}
	for i, m := range decodeAdminProtoWrites(t, conn) {
		if m.Code != protocol.ErrCodeAuthorizationDenied {
			t.Fatalf("auth_only response %d = %+v", i, m)
		}
	}

	session.authenticatedOnly = false
	conn.writes = nil
	for _, frame := range frames {
		session.Dispatch([]byte(frame))
	}
	if got := strings.Join(svc.sourceTokenCalls, " "); got != "set remove list:default" {
		t.Fatalf("service calls = %q", got)
	}
	if string(svc.lastSourceToken) != testSourceToken {
		t.Fatalf("the set reached the service with %q", svc.lastSourceToken)
	}
	types := []string{}
	for _, m := range decodeAdminProtoWrites(t, conn) {
		types = append(types, m.Type)
	}
	if strings.Join(types, " ") != "source_token_set_result source_token_remove_result source_token_list_result" {
		t.Fatalf("response types = %v", types)
	}
}

func TestSourceTokenListResultProjection(t *testing.T) {
	setAt := time.Date(2026, 11, 21, 1, 2, 3, 0, time.FixedZone("x", 3600))
	msg := ProtocolSourceTokenListResultMessage("ls-1", adminproto.ListSourceTokensResult{
		Success: true, Omitted: 2,
		Selectors: []adminproto.SourceTokenSelector{{
			Selector: "default", Policy: adminproto.SourceTokenPolicyOwn, Sources: []string{"ops", "screening"},
			Tokens: []adminproto.SourceTokenInfo{
				{Source: "old", SetAt: setAt, State: adminproto.SourceTokenUnused},
				{Source: "screening", State: adminproto.SourceTokenNeeded},
			},
		}},
	})
	want := protocol.SourceTokenListResultMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSourceTokenListResult, ID: "ls-1"},
		Success:     true, Omitted: 2,
		Selectors: []protocol.SourceTokenSelector{{
			Selector: "default", Policy: "own", Sources: []string{"ops", "screening"},
			Tokens: []protocol.SourceTokenInfo{
				{Source: "old", SetAt: "2026-11-21T00:02:03Z", State: "unused"},
				{Source: "screening", State: "needed"},
			},
		}},
	}
	if fmt.Sprintf("%+v", msg) != fmt.Sprintf("%+v", want) {
		t.Fatalf("projection\n got %+v\nwant %+v", msg, want)
	}
}

// A listing of every selector pages with after, which the handler hands on.
func TestSourceTokenListPassesAfterOn(t *testing.T) {
	svc := &stubServices{}
	session, _, _ := boundSourceTokenSession(svc, &mutationAudit{})
	session.HandleListSourceTokens(&protocol.SourceTokenListMessage{
		BaseMessage: protocol.BaseMessage{ID: "ls-page", Type: protocol.MsgTypeSourceTokenList}, After: "KEY3",
	})
	if got := strings.Join(svc.sourceTokenCalls, " "); got != "list:@KEY3" {
		t.Fatalf("service calls = %q", got)
	}
}

// actionAuthorizer allows the actions in allow and denies the rest.
type actionAuthorizer struct{ allow map[auth.Action]bool }

func (a actionAuthorizer) Authorize(_ context.Context, _ *auth.Identity, action auth.Action, _ auth.Resource) error {
	if a.allow[action] {
		return nil
	}
	return auth.ErrForbidden
}

// Token names are read at policy.update, as source_token_list reads them. A
// check from a session with policy.view alone runs, but the service is told
// the session may not see token names, so it gives no missing-token warning;
// asking is not a request, so no denial is audited for it.
func TestCheckPolicyLetsOnlyPolicyUpdateSeeTokenNames(t *testing.T) {
	for _, tt := range []struct {
		name     string
		allow    []auth.Action
		readable bool
	}{
		{"policy.view only", []auth.Action{auth.ActionPolicyView}, false},
		{"policy.view and policy.update", []auth.Action{auth.ActionPolicyView, auth.ActionPolicyUpdate}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			allow := map[auth.Action]bool{}
			for _, action := range tt.allow {
				allow[action] = true
			}
			svc := &stubServices{checkPolicyResult: adminproto.CheckPolicyResult{Success: true, Valid: true}}
			audit := &recordingAuthorizationAudit{}
			session := NewSession(&queueConn{}, SessionDeps{Product: svc, Settings: svc, Authorizer: actionAuthorizer{allow: allow}, Audit: audit}, OriginLocal)
			session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, productruntime.New(productruntime.Config{}))
			session.HandleCheckPolicy(&protocol.CheckPolicyMessage{
				BaseMessage: protocol.BaseMessage{ID: "check-1", Type: protocol.MsgTypeCheckPolicy},
				Documents:   []protocol.PolicyDocumentWire{{Key: "default", Document: "{}"}},
			})
			if svc.checkPolicyCalls != 1 || svc.lastCheckPolicy.SourceTokensReadable != tt.readable {
				t.Fatalf("check calls = %d, SourceTokensReadable = %v; want 1, %v", svc.checkPolicyCalls, svc.lastCheckPolicy.SourceTokensReadable, tt.readable)
			}
			if audit.calls != 0 {
				t.Fatalf("%d authorization denials audited for a permission question", audit.calls)
			}
		})
	}
}
