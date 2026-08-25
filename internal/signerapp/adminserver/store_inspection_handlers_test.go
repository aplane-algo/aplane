// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

type inspectionStub struct {
	listCalls   int
	importCalls int
	removeCalls int
	listResult  adminproto.ListSentryReferencesResult
}

func (s *inspectionStub) ListSentryReferences() adminproto.ListSentryReferencesResult {
	s.listCalls++
	return s.listResult
}
func (*inspectionStub) GetSentryReference(adminproto.GetSentryReferenceRequest) adminproto.GetSentryReferenceResult {
	return adminproto.GetSentryReferenceResult{}
}
func (s *inspectionStub) ImportSentryReference(adminproto.ImportSentryReferenceRequest) adminproto.ImportSentryReferenceResult {
	s.importCalls++
	return adminproto.ImportSentryReferenceResult{Success: true}
}
func (s *inspectionStub) RemoveSentryReference(adminproto.RemoveSentryReferenceRequest) adminproto.RemoveSentryReferenceResult {
	s.removeCalls++
	return adminproto.RemoveSentryReferenceResult{Success: true}
}

func (*inspectionStub) ExportSentryPublic(adminproto.ExportSentryPublicRequest) adminproto.ExportSentryPublicResult {
	return adminproto.ExportSentryPublicResult{}
}
func (*inspectionStub) ListGenerations() adminproto.GenerationInventory {
	return adminproto.GenerationInventory{}
}

func TestHandleSentryReferenceMutationsRejectLockedIdentity(t *testing.T) {
	ir := productruntime.New(productruntime.Config{Authenticator: auth.NewTokenAuthenticator("token")})
	if ir.IsUnlocked() {
		t.Fatal("new product runtime unexpectedly unlocked")
	}
	inspection := &inspectionStub{}
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{Inspection: inspection, Authorizer: &recordingAuthorizer{}})
	session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)

	session.HandleImportSentryReference(&protocol.ImportSentryReferenceMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeImportSentryReference, ID: "import-sentry"},
		Name:        "lab", EnvelopeJSON: `{}`,
	})
	session.HandleRemoveSentryReference(&protocol.RemoveSentryReferenceMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRemoveSentryReference, ID: "remove-sentry"},
		Name:        "lab",
	})

	if inspection.importCalls != 0 || inspection.removeCalls != 0 {
		t.Fatalf("mutation calls = import:%d remove:%d, want none", inspection.importCalls, inspection.removeCalls)
	}
	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 2 || msgs[0].Code != protocol.ErrCodeSignerLocked || msgs[1].Code != protocol.ErrCodeSignerLocked {
		t.Fatalf("responses = %#v, want two signer_locked errors", msgs)
	}
}

func TestHandleListSentryReferencesAuthorizesBeforeReading(t *testing.T) {
	ir := productruntime.New(productruntime.Config{Authenticator: auth.NewTokenAuthenticator("token")})
	inspection := &inspectionStub{listResult: adminproto.ListSentryReferencesResult{
		References: []adminproto.SentryReferenceInfo{{Name: "lab", ComponentKey: "WKID", KeyType: "witness"}},
	}}
	authorizer := &recordingAuthorizer{}
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{Inspection: inspection, Authorizer: authorizer})
	session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)

	session.HandleListSentryReferences("list-sentries")

	if inspection.listCalls != 1 {
		t.Fatalf("ListSentryReferences calls = %d, want 1", inspection.listCalls)
	}
	if authorizer.got.action != auth.ActionSentriesView || authorizer.got.resource.Type != "sentry_references" {
		t.Fatalf("authorization = %q %+v", authorizer.got.action, authorizer.got.resource)
	}
	var response protocol.SentryReferencesListMessage
	if err := decodeSingleWrite(conn, &response); err != nil {
		t.Fatal(err)
	}
	if response.Type != protocol.MsgTypeSentryReferencesList || len(response.References) != 1 || response.References[0].Name != "lab" {
		t.Fatalf("response = %#v", response)
	}
}

func TestHandleImportSentryReferenceDenialStopsMutation(t *testing.T) {
	ir := productruntime.New(productruntime.Config{Authenticator: auth.NewTokenAuthenticator("token")})
	ir.SetUnlocked()
	inspection := &inspectionStub{}
	authorizer := &recordingAuthorizer{err: auth.ErrForbidden}
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{Inspection: inspection, Authorizer: authorizer})
	session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)

	session.HandleImportSentryReference(&protocol.ImportSentryReferenceMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeImportSentryReference, ID: "import-sentry"},
		Name:        "lab", EnvelopeJSON: `{}`,
	})

	if inspection.importCalls != 0 {
		t.Fatalf("ImportSentryReference calls = %d, want 0", inspection.importCalls)
	}
	if authorizer.got.action != auth.ActionSentriesManage {
		t.Fatalf("authorization action = %q, want %q", authorizer.got.action, auth.ActionSentriesManage)
	}
	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 1 || msgs[0].Code != protocol.ErrCodeAuthorizationDenied {
		t.Fatalf("responses = %#v", msgs)
	}
}

func decodeSingleWrite(conn *queueConn, out any) error {
	if len(conn.writes) != 1 {
		return protocol.WithCode("test", &writeCountError{got: len(conn.writes)})
	}
	return json.Unmarshal(conn.writes[0], out)
}

type writeCountError struct{ got int }

func (e *writeCountError) Error() string { return fmt.Sprintf("write count = %d, want 1", e.got) }
