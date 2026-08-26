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
	listCalls          int
	importCalls        int
	removeCalls        int
	pruneCalls         int
	archiveListCalls   int
	archivePruneCalls  int
	lastPrune          adminproto.PruneGenerationQuarantineRequest
	lastArchivePrune   adminproto.PruneDeletedArchiveRequest
	pruneResult        adminproto.PruneGenerationQuarantineResult
	archiveListResult  adminproto.DeletedArchiveInventory
	archivePruneResult adminproto.PruneDeletedArchiveResult
	listResult         adminproto.ListSentryReferencesResult
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
func (s *inspectionStub) PruneGenerationQuarantine(
	req adminproto.PruneGenerationQuarantineRequest,
) adminproto.PruneGenerationQuarantineResult {
	s.pruneCalls++
	s.lastPrune = req
	return s.pruneResult
}
func (s *inspectionStub) ListDeletedArchive() adminproto.DeletedArchiveInventory {
	s.archiveListCalls++
	return s.archiveListResult
}
func (s *inspectionStub) PruneDeletedArchive(req adminproto.PruneDeletedArchiveRequest) adminproto.PruneDeletedArchiveResult {
	s.archivePruneCalls++
	s.lastArchivePrune = req
	return s.archivePruneResult
}

type quarantinePruneAudit struct {
	recordingAuthorizationAudit
	intentCalls   int
	outcomeCalls  int
	intentErr     error
	operationID   string
	generationIDs []string
}

type archivePruneAudit struct {
	recordingAuthorizationAudit
	intentCalls  int
	outcomeCalls int
	intentErr    error
	operationID  string
	entries      []string
}

func (a *archivePruneAudit) LogDeletedArchivePruneIntentDurableContext(
	_ SessionContext,
	operationID string,
	entries []string,
) error {
	a.intentCalls++
	a.operationID = operationID
	a.entries = append([]string(nil), entries...)
	return a.intentErr
}

func (a *archivePruneAudit) LogDeletedArchivePruneContext(
	_ SessionContext,
	operationID string,
	_ adminproto.PruneDeletedArchiveResult,
) {
	a.outcomeCalls++
	a.operationID = operationID
}

func (a *quarantinePruneAudit) LogGenerationQuarantinePruneIntentDurableContext(
	_ SessionContext,
	operationID string,
	generationIDs []string,
) error {
	a.intentCalls++
	a.operationID = operationID
	a.generationIDs = append([]string(nil), generationIDs...)
	return a.intentErr
}

func (a *quarantinePruneAudit) LogGenerationQuarantinePruneContext(
	_ SessionContext,
	operationID string,
	_ adminproto.PruneGenerationQuarantineResult,
) {
	a.outcomeCalls++
	a.operationID = operationID
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

func TestHandlePruneGenerationQuarantineRequiresAuditBeforeMutation(t *testing.T) {
	const generationID = "gen-1700000000-0123abcd"
	ir := productruntime.New(productruntime.Config{Authenticator: auth.NewTokenAuthenticator("token")})
	ir.SetUnlocked()
	inspection := &inspectionStub{pruneResult: adminproto.PruneGenerationQuarantineResult{
		Success: true,
		Pruned:  []adminproto.PrunedQuarantinedGeneration{{GenerationID: generationID, EncodedBytes: 12}},
	}}
	authorizer := &recordingAuthorizer{}
	audit := &quarantinePruneAudit{}
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{
		Inspection: inspection,
		Authorizer: authorizer,
		Audit:      audit,
	})
	session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)

	session.HandlePruneGenerationQuarantine(&protocol.PruneGenerationQuarantineMessage{
		BaseMessage:   protocol.BaseMessage{Type: protocol.MsgTypePruneGenerationQuarantine, ID: "prune-1"},
		GenerationIDs: []string{generationID},
		Confirm:       true,
	})

	if authorizer.got.action != auth.ActionGenerationQuarantinePrune ||
		authorizer.got.resource.Type != "generation_quarantine" {
		t.Fatalf("authorization = %q %+v", authorizer.got.action, authorizer.got.resource)
	}
	if audit.intentCalls != 1 || audit.outcomeCalls != 1 || audit.operationID != "prune-1" {
		t.Fatalf("audit calls = intent:%d outcome:%d operation:%q", audit.intentCalls, audit.outcomeCalls, audit.operationID)
	}
	if inspection.pruneCalls != 1 || len(inspection.lastPrune.GenerationIDs) != 1 ||
		inspection.lastPrune.GenerationIDs[0] != generationID {
		t.Fatalf("prune service calls=%d request=%#v", inspection.pruneCalls, inspection.lastPrune)
	}
	var response protocol.PruneGenerationQuarantineResultMessage
	if err := decodeSingleWrite(conn, &response); err != nil {
		t.Fatal(err)
	}
	if !response.Success || len(response.Pruned) != 1 || response.Pruned[0].GenerationID != generationID {
		t.Fatalf("response = %#v", response)
	}
}

func TestHandlePruneGenerationQuarantineFailsClosedWithoutConfirmationOrAudit(t *testing.T) {
	const generationID = "gen-1700000000-0123abcd"
	for _, test := range []struct {
		name     string
		confirm  bool
		audit    AuthorizationAudit
		wantCode string
	}{
		{
			name:     "confirmation required",
			confirm:  false,
			audit:    &quarantinePruneAudit{},
			wantCode: protocol.ResultCodeConfirmationRequired,
		},
		{
			name:     "durable audit required",
			confirm:  true,
			audit:    &recordingAuthorizationAudit{},
			wantCode: protocol.ResultCodeQuarantineAuditFailed,
		},
		{
			name:     "durable audit failure",
			confirm:  true,
			audit:    &quarantinePruneAudit{intentErr: fmt.Errorf("disk full")},
			wantCode: protocol.ResultCodeQuarantineAuditFailed,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ir := productruntime.New(productruntime.Config{Authenticator: auth.NewTokenAuthenticator("token")})
			ir.SetUnlocked()
			inspection := &inspectionStub{}
			conn := &queueConn{}
			session := NewSession(conn, SessionDeps{
				Inspection: inspection,
				Authorizer: &recordingAuthorizer{},
				Audit:      test.audit,
			})
			session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)
			session.HandlePruneGenerationQuarantine(&protocol.PruneGenerationQuarantineMessage{
				BaseMessage:   protocol.BaseMessage{Type: protocol.MsgTypePruneGenerationQuarantine, ID: "prune-fail"},
				GenerationIDs: []string{generationID},
				Confirm:       test.confirm,
			})
			if inspection.pruneCalls != 0 {
				t.Fatalf("prune service called %d times", inspection.pruneCalls)
			}
			var response protocol.PruneGenerationQuarantineResultMessage
			if err := decodeSingleWrite(conn, &response); err != nil {
				t.Fatal(err)
			}
			if response.Code != test.wantCode {
				t.Fatalf("response code = %q, want %q", response.Code, test.wantCode)
			}
		})
	}
}

func TestHandleListDeletedArchiveAuthorizesBeforeReading(t *testing.T) {
	ir := productruntime.New(productruntime.Config{Authenticator: auth.NewTokenAuthenticator("token")})
	ir.SetUnlocked()
	inspection := &inspectionStub{archiveListResult: adminproto.DeletedArchiveInventory{
		Entries:    []adminproto.DeletedArchiveEntry{{Path: "deleted/keys/A.key", EncodedBytes: 12}},
		EntryCount: 1, EncodedBytes: 12,
	}}
	authorizer := &recordingAuthorizer{}
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{Inspection: inspection, Authorizer: authorizer})
	session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)

	session.HandleListDeletedArchive("archive-list")

	if inspection.archiveListCalls != 1 {
		t.Fatalf("ListDeletedArchive calls = %d, want 1", inspection.archiveListCalls)
	}
	if authorizer.got.action != auth.ActionGenerationsView || authorizer.got.resource.Type != "deleted_archive" {
		t.Fatalf("authorization = %q %+v", authorizer.got.action, authorizer.got.resource)
	}
	var response protocol.DeletedArchiveListMessage
	if err := decodeSingleWrite(conn, &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Entries) != 1 || response.Entries[0].Path != "deleted/keys/A.key" {
		t.Fatalf("response = %#v", response)
	}
}

func TestHandlePruneDeletedArchiveRequiresAuthorizationAndDurableAudit(t *testing.T) {
	ir := productruntime.New(productruntime.Config{Authenticator: auth.NewTokenAuthenticator("token")})
	ir.SetUnlocked()
	inspection := &inspectionStub{archivePruneResult: adminproto.PruneDeletedArchiveResult{
		Success: true,
		Pruned:  []adminproto.PrunedDeletedArchiveEntry{{Path: "deleted/keys/A.key", EncodedBytes: 12}},
	}}
	authorizer := &recordingAuthorizer{}
	audit := &archivePruneAudit{}
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{Inspection: inspection, Authorizer: authorizer, Audit: audit})
	session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)

	session.HandlePruneDeletedArchive(&protocol.PruneDeletedArchiveMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypePruneDeletedArchive, ID: "archive-prune"},
		Entries:     []string{"deleted/keys/A.key"}, Confirm: true,
	})

	if authorizer.got.action != auth.ActionArchivePrune || authorizer.got.resource.Type != "deleted_archive" {
		t.Fatalf("authorization = %q %+v", authorizer.got.action, authorizer.got.resource)
	}
	if audit.intentCalls != 1 || audit.outcomeCalls != 1 || audit.operationID != "archive-prune" {
		t.Fatalf("audit = intent:%d outcome:%d operation:%q", audit.intentCalls, audit.outcomeCalls, audit.operationID)
	}
	if inspection.archivePruneCalls != 1 || len(inspection.lastArchivePrune.Entries) != 1 {
		t.Fatalf("prune calls=%d request=%#v", inspection.archivePruneCalls, inspection.lastArchivePrune)
	}
}

func TestHandlePruneDeletedArchiveFailsClosedBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name         string
		confirm      bool
		authorizeErr error
		audit        AuthorizationAudit
		wantCode     string
	}{
		{name: "authorization", confirm: true, authorizeErr: auth.ErrForbidden, audit: &archivePruneAudit{}, wantCode: protocol.ErrCodeAuthorizationDenied},
		{name: "confirmation", audit: &archivePruneAudit{}, wantCode: protocol.ResultCodeConfirmationRequired},
		{name: "audit unavailable", confirm: true, audit: &recordingAuthorizationAudit{}, wantCode: protocol.ResultCodeArchiveAuditFailed},
		{name: "audit failure", confirm: true, audit: &archivePruneAudit{intentErr: fmt.Errorf("disk full")}, wantCode: protocol.ResultCodeArchiveAuditFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			ir := productruntime.New(productruntime.Config{Authenticator: auth.NewTokenAuthenticator("token")})
			ir.SetUnlocked()
			inspection := &inspectionStub{}
			conn := &queueConn{}
			session := NewSession(conn, SessionDeps{Inspection: inspection, Authorizer: &recordingAuthorizer{err: test.authorizeErr}, Audit: test.audit})
			session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)
			session.HandlePruneDeletedArchive(&protocol.PruneDeletedArchiveMessage{
				BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypePruneDeletedArchive, ID: "archive-prune-fail"},
				Entries:     []string{"deleted/keys/A.key"}, Confirm: test.confirm,
			})
			if inspection.archivePruneCalls != 0 {
				t.Fatalf("archive prune called %d times", inspection.archivePruneCalls)
			}
			msgs := decodeAdminProtoWrites(t, conn)
			if len(msgs) != 1 || msgs[0].Code != test.wantCode {
				t.Fatalf("responses = %#v, want code %q", msgs, test.wantCode)
			}
		})
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
