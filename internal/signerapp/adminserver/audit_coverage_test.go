// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

// auditedByHandler is the audit methods a command's handler calls, when the
// service behind it succeeds and when it fails.
var auditedByHandler = map[string]struct{ success, failure []string }{
	// A lock cannot fail.
	protocol.MsgTypeLockIdentity: {[]string{"LogIdentityLockedContext"}, []string{"LogIdentityLockedContext"}},
	protocol.MsgTypeBackup:       {[]string{"LogBackupCreatedContext"}, []string{"LogBackupFailedContext"}},
	protocol.MsgTypeDeleteBackup: {[]string{"LogBackupDeletedContext"}, []string{"LogBackupDeletedContext"}},
	protocol.MsgTypeCommitBackupImport: {
		[]string{"LogBackupImportedContext"}, []string{"LogBackupFailedContext"},
	},
	protocol.MsgTypeReadBackupChunk: {
		[]string{"LogBackupExportStartedContext"}, []string{"LogBackupFailedContext"},
	},
	protocol.MsgTypePreviewRestore: {
		[]string{"LogBackupRestorePreviewedContext"}, []string{"LogBackupRestorePreviewFailedContext"},
	},
	protocol.MsgTypeRestoreBackup: {
		[]string{"LogCredentialRestoreIntentDurableContext", "LogCredentialRestoreContext"},
		[]string{"LogCredentialRestoreIntentDurableContext", "LogCredentialRestoreContext"},
	},
	protocol.MsgTypeRollbackRestore: {
		[]string{"LogCredentialRestoreRollbackContext"}, []string{"LogCredentialRestoreRollbackContext"},
	},
	protocol.MsgTypeReconcileStore: {
		[]string{"LogStoreReconciledContext"}, []string{"LogStoreReconciledContext"},
	},
	// A setting's change is recorded by its service, and a failed save by the
	// handler.
	protocol.MsgTypeUpdateAdminSetting: {failure: []string{"LogSettingSaveErrorContext"}},
	protocol.MsgTypeApplyPolicy: {
		[]string{"LogPolicyApplyIntentDurableContext", "LogPolicyApplyResultContext"},
		[]string{"LogPolicyApplyIntentDurableContext", "LogPolicyApplyResultContext"},
	},
	protocol.MsgTypeAddASA: {
		[]string{"LogASASetUpdateIntentDurableContext", "LogASASetAddResultContext"},
		[]string{"LogASASetUpdateIntentDurableContext", "LogASASetAddResultContext"},
	},
	protocol.MsgTypeRemoveASA: {
		[]string{"LogASASetUpdateIntentDurableContext", "LogASASetRemoveResultContext"},
		[]string{"LogASASetUpdateIntentDurableContext", "LogASASetRemoveResultContext"},
	},
	protocol.MsgTypeSourceTokenSet: {
		[]string{"LogSourceTokenChangeIntentDurableContext", "LogSourceTokenChangeResultContext"},
		[]string{"LogSourceTokenChangeIntentDurableContext", "LogSourceTokenChangeResultContext"},
	},
	protocol.MsgTypeSourceTokenRemove: {
		[]string{"LogSourceTokenChangeIntentDurableContext", "LogSourceTokenChangeResultContext"},
		[]string{"LogSourceTokenChangeIntentDurableContext", "LogSourceTokenChangeResultContext"},
	},
	protocol.MsgTypeImportCosignerReference: {
		[]string{"LogCosignerReferenceChangedContext"}, []string{"LogCosignerReferenceChangedContext"},
	},
	protocol.MsgTypeRemoveCosignerReference: {
		[]string{"LogCosignerReferenceChangedContext"}, []string{"LogCosignerReferenceChangedContext"},
	},
	protocol.MsgTypePruneGenerationQuarantine: {
		[]string{"LogGenerationQuarantinePruneIntentDurableContext", "LogGenerationQuarantinePruneContext"},
		[]string{"LogGenerationQuarantinePruneIntentDurableContext", "LogGenerationQuarantinePruneContext"},
	},
	protocol.MsgTypeDiscardAbandonedGenerations: {
		[]string{"LogGenerationAbandonedDiscardIntentDurableContext", "LogGenerationAbandonedDiscardContext"},
		[]string{"LogGenerationAbandonedDiscardIntentDurableContext", "LogGenerationAbandonedDiscardContext"},
	},
	protocol.MsgTypePruneDeletedArchive: {
		[]string{"LogDeletedArchivePruneIntentDurableContext", "LogDeletedArchivePruneContext"},
		[]string{"LogDeletedArchivePruneIntentDurableContext", "LogDeletedArchivePruneContext"},
	},
	protocol.MsgTypeInstallLibraryTemplate: {
		[]string{"LogKeyTypeChangedContext"}, []string{"LogKeyTypeChangedContext"},
	},
	protocol.MsgTypeImportInstalledTemplate: {
		[]string{"LogKeyTypeChangedContext"}, []string{"LogKeyTypeChangedContext"},
	},
	protocol.MsgTypeRemoveInstalledTemplate: {
		[]string{"LogKeyTypeChangedContext"}, []string{"LogKeyTypeChangedContext"},
	},
	protocol.MsgTypeActivateKeyType: {
		[]string{"LogKeyTypeChangedContext"}, []string{"LogKeyTypeChangedContext"},
	},
	protocol.MsgTypeDeactivateKeyType: {
		[]string{"LogKeyTypeChangedContext"}, []string{"LogKeyTypeChangedContext"},
	},
}

// auditedByService is the commands recorded in the service behind the handler,
// which their own tests check, and where.
var auditedByService = map[string]string{
	protocol.MsgTypeUnlock:                "daemon.Signer.recordUnlock",
	protocol.MsgTypeUpdateAdminSetting:    "signerapp/admin",
	protocol.MsgTypeChangeStorePass:       "signerapp/storeadmin",
	protocol.MsgTypeRevokeEnrolledKey:     "daemon.Signer.RevokeClientKey",
	protocol.MsgTypeRevokeAllEnrolledKeys: "daemon.Signer.RevokeAllClientKeys",
	protocol.MsgTypeApproveEnrollment:     "daemon.Signer.ApproveClientEnrollment",
	protocol.MsgTypeRejectEnrollment:      "daemon.Signer.RejectClientEnrollment",
	protocol.MsgTypeImportClientKey:       "daemon.Signer.ImportClientKey",
	protocol.MsgTypeGenerateKey:           "signerapp/keyadmin",
	protocol.MsgTypeDeleteKey:             "signerapp/keyadmin",
	protocol.MsgTypeExportKey:             "signerapp/keyadmin",
	protocol.MsgTypeImportKey:             "signerapp/keyadmin",
	protocol.MsgTypeSignResponse:          "signerapp/signing",
}

// unaudited is the commands that change nothing lasting. An import in progress
// is one: what it publishes is recorded by its commit.
var unaudited = map[string]bool{
	protocol.MsgTypeBeginBackupImport:      true,
	protocol.MsgTypeAppendBackupImport:     true,
	protocol.MsgTypeAbortBackupImport:      true,
	protocol.MsgTypeListBackups:            true,
	protocol.MsgTypeListEnrolledKeys:       true,
	protocol.MsgTypeListPendingEnrollments: true,
	protocol.MsgTypeGetAdminSettings:       true,
	protocol.MsgTypeGetPolicy:              true,
	protocol.MsgTypeGetPolicyDocument:      true,
	protocol.MsgTypeGetPolicyContext:       true,
	protocol.MsgTypeCheckPolicy:            true,
	protocol.MsgTypeListASASet:             true,
	protocol.MsgTypeLookupASA:              true,
	protocol.MsgTypeSourceTokenList:        true,
	protocol.MsgTypeListCosignerReferences: true,
	protocol.MsgTypeGetCosignerReference:   true,
	protocol.MsgTypeExportCosignerPublic:   true,
	protocol.MsgTypeListGenerations:        true,
	protocol.MsgTypeListDeletedArchive:     true,
	protocol.MsgTypeListKeys:               true,
	protocol.MsgTypeGetKeyDetails:          true,
	protocol.MsgTypePrepareGenerateKey:     true,
	protocol.MsgTypeListLibraryTemplates:   true,
	protocol.MsgTypeListInstalledTemplates: true,
	protocol.MsgTypeShowInstalledTemplate:  true,
	protocol.MsgTypeShowLibraryTemplate:    true,
	protocol.MsgTypeListKeyTypes:           true,
}

// outcomeSettings answers a setting update with err.
type outcomeSettings struct {
	*stubServices
	err error
}

func (o outcomeSettings) UpdateAdminSetting(context.Context, adminproto.UpdateAdminSettingRequest) error {
	return o.err
}

// Every admin command is recorded by its handler, recorded by its service, or
// changes nothing lasting. A command added to the dispatch table without being
// placed in one of the three fails here, and so does a handler that drops a
// record.
func TestEveryAdminCommandIsRecordedOrChangesNothing(t *testing.T) {
	samples := allDispatchRequestSamples()
	for msgType := range dispatchTable {
		expected, byHandler := auditedByHandler[msgType]
		_, byService := auditedByService[msgType]
		if byHandler && !byService && (len(expected.success) == 0 || len(expected.failure) == 0) {
			t.Errorf("%s names no audit method for an outcome, and no service records it", msgType)
		}
		if unaudited[msgType] == (byHandler || byService) {
			t.Errorf("%s: recorded by handler %t, by service %t, unaudited %t; want it recorded or unaudited", msgType, byHandler, byService, unaudited[msgType])
			continue
		}
		if !byHandler && !unaudited[msgType] {
			continue
		}
		for outcome, want := range map[bool][]string{true: expected.success, false: expected.failure} {
			if got := auditCalls(t, samples[msgType], outcome); !reflect.DeepEqual(got, want) {
				t.Errorf("%s (success %t) recorded %v, want %v", msgType, outcome, got, want)
			}
		}
	}
	listed := map[string]bool{}
	for msgType := range auditedByHandler {
		listed[msgType] = true
	}
	for msgType := range auditedByService {
		listed[msgType] = true
	}
	for msgType := range unaudited {
		listed[msgType] = true
	}
	for msgType := range listed {
		if dispatchTable[msgType] == nil {
			t.Errorf("%s is listed but not dispatched", msgType)
		}
	}
}

// auditCalls dispatches a populated sample with services that succeed or fail,
// and returns the audit methods the handler called.
func auditCalls(t *testing.T, sample any, success bool) []string {
	t.Helper()
	ir := productruntime.New(productruntime.Config{})
	ir.SetUnlocked()
	svc := &stubServices{runtime: ir}
	inspection := &inspectionStub{}
	setOutcomes(reflect.ValueOf(svc).Elem(), success)
	setOutcomes(reflect.ValueOf(inspection).Elem(), success)
	settings := outcomeSettings{stubServices: svc}
	if !success {
		settings.err = &adminproto.SettingSaveError{Key: "k", Value: "v", Err: errors.New("disk full")}
	}
	audit := &stubAudit{durable: true}
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{
		Product: svc, Settings: settings, Keys: svc, Backups: svc, Templates: svc,
		Inspection: inspection, Authorizer: &recordingAuthorizer{}, Audit: audit,
	}, OriginLocal)
	session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)
	raw, err := protocol.MarshalAdminMessage(populateRequestSample(sample))
	if err != nil {
		t.Fatal(err)
	}
	session.Dispatch(raw)
	for _, w := range decodeAdminProtoWrites(t, conn) {
		if w.Type == protocol.MsgTypeError {
			t.Fatalf("%T was refused before its service: %+v", sample, w)
		}
	}
	for i, ctx := range audit.sessions {
		if ctx.AdminPrincipal.ID != "admin-principal" || ctx.SessionID != session.SessionContext().SessionID {
			t.Errorf("%s is for %q in session %q, want the session that sent it", audit.calls[i], ctx.AdminPrincipal.ID, ctx.SessionID)
		}
	}
	return audit.calls
}

// setOutcomes makes every result a stub's field holds succeed or fail.
func setOutcomes(stub reflect.Value, success bool) {
	for i := range stub.NumField() {
		field := stub.Field(i)
		if field.Kind() != reflect.Struct {
			continue
		}
		ok, errText := field.FieldByName("Success"), field.FieldByName("Error")
		if !errText.IsValid() {
			continue
		}
		field = reflect.NewAt(field.Type(), field.Addr().UnsafePointer()).Elem()
		if ok.IsValid() {
			field.FieldByName("Success").SetBool(success)
		}
		if !success {
			field.FieldByName("Error").SetString("failed")
		}
	}
}

// keyTypeAudit keeps the key type changes it is given.
type keyTypeAudit struct {
	stubAudit
	changes []KeyTypeChange
}

func (a *keyTypeAudit) LogKeyTypeChangedContext(_ SessionContext, change KeyTypeChange) {
	a.changes = append(a.changes, change)
}

// A key type entry says whether the store changed when the answer tells: a
// success does, a failure to add one does not, and a removal whose reload
// failed stayed.
func TestKeyTypeRecordsSayWhetherTheStoreChanged(t *testing.T) {
	const code, text = "reload_failed", "reload_failed text"
	for _, tc := range []struct {
		name    string
		svc     stubServices
		msgType string
		want    string
	}{
		{"installed", stubServices{installResult: adminproto.InstallLibraryTemplateResult{Success: true, KeyType: "k"}}, protocol.MsgTypeInstallLibraryTemplate, "install k true changed"},
		{"already installed", stubServices{installResult: adminproto.InstallLibraryTemplateResult{Success: true, KeyType: "k", AlreadyExists: true}}, protocol.MsgTypeInstallLibraryTemplate, "install k true unchanged"},
		{"install failed", stubServices{installResult: adminproto.InstallLibraryTemplateResult{KeyType: "k", Code: code, Error: text}}, protocol.MsgTypeInstallLibraryTemplate, "install k false unsaid reload_failed reload_failed text"},
		{"imported", stubServices{importInstalledResult: adminproto.ImportInstalledTemplateResult{Success: true, KeyType: "k"}}, protocol.MsgTypeImportInstalledTemplate, "import k true changed"},
		{"import failed", stubServices{importInstalledResult: adminproto.ImportInstalledTemplateResult{Code: code, Error: text}}, protocol.MsgTypeImportInstalledTemplate, "import  false unsaid reload_failed reload_failed text"},
		{"activated", stubServices{activateResult: adminproto.ActivateKeyTypeResult{Success: true, KeyType: "k"}}, protocol.MsgTypeActivateKeyType, "activate k true changed"},
		{"already active", stubServices{activateResult: adminproto.ActivateKeyTypeResult{Success: true, KeyType: "k", AlreadyExists: true}}, protocol.MsgTypeActivateKeyType, "activate k true unchanged"},
		{"removed", stubServices{removeInstalledResult: adminproto.RemoveInstalledTemplateResult{Success: true, KeyType: "k", Removed: true}}, protocol.MsgTypeRemoveInstalledTemplate, "remove k true changed"},
		{"nothing to remove", stubServices{removeInstalledResult: adminproto.RemoveInstalledTemplateResult{Success: true, KeyType: "k"}}, protocol.MsgTypeRemoveInstalledTemplate, "remove k true unchanged"},
		{"removed, reload failed", stubServices{removeInstalledResult: adminproto.RemoveInstalledTemplateResult{KeyType: "k", Removed: true, Code: code, Error: text}}, protocol.MsgTypeRemoveInstalledTemplate, "remove k false changed reload_failed reload_failed text"},
		{"remove failed", stubServices{removeInstalledResult: adminproto.RemoveInstalledTemplateResult{KeyType: "k", Code: code, Error: text}}, protocol.MsgTypeRemoveInstalledTemplate, "remove k false unsaid reload_failed reload_failed text"},
		{"deactivated, reload failed", stubServices{deactivateResult: adminproto.DeactivateKeyTypeResult{KeyType: "k", Removed: true, Code: code, Error: text}}, protocol.MsgTypeDeactivateKeyType, "deactivate k false changed reload_failed reload_failed text"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ir := productruntime.New(productruntime.Config{})
			ir.SetUnlocked()
			audit := &keyTypeAudit{}
			deps := tc.svc.templateDeps()
			deps.Audit = audit
			session := NewSession(&queueConn{}, deps, OriginLocal)
			session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)
			raw, err := protocol.MarshalAdminMessage(populateRequestSample(allDispatchRequestSamples()[tc.msgType]))
			if err != nil {
				t.Fatal(err)
			}
			session.Dispatch(raw)
			if len(audit.changes) != 1 {
				t.Fatalf("recorded %+v, want one change", audit.changes)
			}
			c := audit.changes[0]
			changed := "unsaid"
			if c.Changed != nil {
				changed = map[bool]string{true: "changed", false: "unchanged"}[*c.Changed]
			}
			got := strings.TrimSpace(fmt.Sprintf("%s %s %t %s %s %s", c.Action, c.KeyType, c.Success, changed, c.Code, c.Error))
			if got != tc.want {
				t.Fatalf("recorded %q, want %q", got, tc.want)
			}
		})
	}
}

// loginAudit keeps the login failures and the denials it is given.
type loginAudit struct {
	stubAudit
	failures  []string
	deniedFor []string
}

func (a *loginAudit) LogAdminLoginFailedContext(_ SessionContext, reason string) {
	a.failures = append(a.failures, reason)
}

func (a *loginAudit) LogAuthorizationDenied(ctx SessionContext, action auth.Action, _ auth.Resource, _ string) {
	a.deniedFor = append(a.deniedFor, ctx.AdminPrincipal.ID+" "+string(action))
}

// A login the authorizer denies is recorded for the principal it was for,
// though the session does not hold one yet.
func TestADeniedLoginIsRecordedForItsPrincipal(t *testing.T) {
	ir := productruntime.New(productruntime.Config{})
	svc := &stubServices{runtime: ir, newIdentity: &auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}}
	audit := &loginAudit{}
	conn := &queueConn{reads: [][]byte{mustAuthFrame(t, "right-secret", "")}}
	session := NewSession(conn, SessionDeps{Product: svc, Authorizer: &recordingAuthorizer{err: auth.ErrForbidden}, Audit: audit}, OriginLocal)
	if got := session.AuthenticateOutcome(); got != AuthOutcomeFailed {
		t.Fatalf("AuthenticateOutcome() = %v, want failed", got)
	}
	if want := "[admin-principal " + string(auth.ActionIdentityUnlock) + "]"; fmt.Sprint(audit.deniedFor) != want {
		t.Fatalf("recorded denials %v, want %s", audit.deniedFor, want)
	}
}

// An unlock command is the session's, which the service records it for.
func TestAnUnlockCommandCarriesItsSession(t *testing.T) {
	ir := productruntime.New(productruntime.Config{})
	svc := &stubServices{runtime: ir, unlockOK: true}
	session := NewSession(&queueConn{}, SessionDeps{Product: svc, Authorizer: &recordingAuthorizer{}, Audit: &stubAudit{}}, OriginLocal)
	session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)
	session.HandleUnlock(&protocol.UnlockMessage{BaseMessage: protocol.BaseMessage{ID: "unlock-1", Type: protocol.MsgTypeUnlock}, Passphrase: protocol.NewSensitiveBytes("right-secret")})
	got, ok := SessionContextFromContext(svc.unlockCtx)
	if !ok || got.AdminPrincipal.ID != "admin-principal" || got.SessionID != session.SessionContext().SessionID {
		t.Fatalf("the unlock ran for %+v, %t; want the session's context", got, ok)
	}
}

// A failure is recorded even if its answer says nothing of why.
func TestABackupFailureWithNoErrorTextIsRecorded(t *testing.T) {
	for _, msgType := range []string{protocol.MsgTypeBackup, protocol.MsgTypeCommitBackupImport, protocol.MsgTypeReadBackupChunk} {
		ir := productruntime.New(productruntime.Config{})
		ir.SetUnlocked()
		audit := &stubAudit{}
		svc := &stubServices{runtime: ir}
		session := NewSession(&queueConn{}, SessionDeps{Product: svc, Backups: svc, Authorizer: &recordingAuthorizer{}, Audit: audit}, OriginLocal)
		session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)
		raw, err := protocol.MarshalAdminMessage(populateRequestSample(allDispatchRequestSamples()[msgType]))
		if err != nil {
			t.Fatal(err)
		}
		session.Dispatch(raw)
		if fmt.Sprint(audit.calls) != "[LogBackupFailedContext]" {
			t.Errorf("%s recorded %v, want its failure", msgType, audit.calls)
		}
	}
}

// answerAudit keeps the answers it is given for a deletion and a reconcile.
type answerAudit struct {
	stubAudit
	got []string
}

func (a *answerAudit) LogBackupDeletedContext(_ SessionContext, path string, result adminproto.DeleteBackupResult) {
	a.got = append(a.got, fmt.Sprintf("%s %t %s %s", path, result.Success, result.Code, result.Error))
}

func (a *answerAudit) LogStoreReconciledContext(_ SessionContext, result adminproto.ReconcileStoreResult) {
	a.got = append(a.got, fmt.Sprintf("%s %t %s %s", result.GenerationID, result.Success, result.Code, result.Error))
}

// A deletion and a reconcile are recorded by the answer the service gave, so
// after it gave one.
func TestDeletionsAndReconcilesRecordTheServicesAnswer(t *testing.T) {
	for _, tc := range []struct {
		svc  stubServices
		want string
	}{
		{stubServices{
			deleteBackupResult:   adminproto.DeleteBackupResult{Success: true},
			reconcileStoreResult: adminproto.ReconcileStoreResult{Success: true, GenerationID: "gen-2"},
		}, "[x true   gen-2 true  ]"},
		{stubServices{
			deleteBackupResult:   adminproto.DeleteBackupResult{Code: "c", Error: "not found"},
			reconcileStoreResult: adminproto.ReconcileStoreResult{Code: "c", Error: "damaged"},
		}, "[x false c not found  false c damaged]"},
	} {
		ir := productruntime.New(productruntime.Config{})
		ir.SetUnlocked()
		audit := &answerAudit{}
		deps := tc.svc.backupDeps()
		deps.Audit = audit
		session := NewSession(&queueConn{}, deps, OriginLocal)
		session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)
		for _, msgType := range []string{protocol.MsgTypeDeleteBackup, protocol.MsgTypeReconcileStore} {
			raw, err := protocol.MarshalAdminMessage(populateRequestSample(allDispatchRequestSamples()[msgType]))
			if err != nil {
				t.Fatal(err)
			}
			session.Dispatch(raw)
		}
		if got := fmt.Sprint(audit.got); got != tc.want {
			t.Errorf("recorded %s, want %s", got, tc.want)
		}
	}
}
