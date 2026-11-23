// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

func allDispatchRequestSamples() map[string]any {
	return map[string]any{
		protocol.MsgTypeUnlock:                      protocol.UnlockMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeUnlock, ID: "r"}},
		protocol.MsgTypeLockIdentity:                protocol.LockIdentityMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeLockIdentity, ID: "r"}},
		protocol.MsgTypeBackup:                      protocol.BackupMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeBackup, ID: "r"}},
		protocol.MsgTypeListBackups:                 protocol.ListBackupsMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListBackups, ID: "r"}},
		protocol.MsgTypeDeleteBackup:                protocol.DeleteBackupMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeDeleteBackup, ID: "r"}},
		protocol.MsgTypeBeginBackupImport:           protocol.BeginBackupImportMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeBeginBackupImport, ID: "r"}},
		protocol.MsgTypeAppendBackupImport:          protocol.AppendBackupImportMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAppendBackupImport, ID: "r"}},
		protocol.MsgTypeCommitBackupImport:          protocol.CommitBackupImportMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeCommitBackupImport, ID: "r"}},
		protocol.MsgTypeAbortBackupImport:           protocol.AbortBackupImportMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAbortBackupImport, ID: "r"}},
		protocol.MsgTypeReadBackupChunk:             protocol.ReadBackupChunkMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeReadBackupChunk, ID: "r"}},
		protocol.MsgTypeChangeStorePass:             protocol.ChangeStorePassphraseMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeChangeStorePass, ID: "r"}},
		protocol.MsgTypePreviewRestore:              protocol.PreviewRestoreMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypePreviewRestore, ID: "r"}},
		protocol.MsgTypeRestoreBackup:               protocol.RestoreBackupMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRestoreBackup, ID: "r"}},
		protocol.MsgTypeRollbackRestore:             protocol.RollbackRestoreMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRollbackRestore, ID: "r"}},
		protocol.MsgTypeReconcileStore:              protocol.ReconcileStoreMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeReconcileStore, ID: "r"}},
		protocol.MsgTypeListEnrolledKeys:            protocol.ListEnrolledKeysMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListEnrolledKeys, ID: "r"}},
		protocol.MsgTypeRevokeEnrolledKey:           protocol.RevokeEnrolledKeyMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRevokeEnrolledKey, ID: "r"}},
		protocol.MsgTypeRevokeAllEnrolledKeys:       protocol.RevokeAllEnrolledKeysMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRevokeAllEnrolledKeys, ID: "r"}},
		protocol.MsgTypeListPendingEnrollments:      protocol.ListPendingEnrollmentsMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListPendingEnrollments, ID: "r"}},
		protocol.MsgTypeApproveEnrollment:           protocol.ApproveEnrollmentMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeApproveEnrollment, ID: "r"}},
		protocol.MsgTypeRejectEnrollment:            protocol.RejectEnrollmentMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRejectEnrollment, ID: "r"}},
		protocol.MsgTypeImportClientKey:             protocol.ImportClientKeyMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeImportClientKey, ID: "r"}},
		protocol.MsgTypeGetAdminSettings:            protocol.GetAdminSettingsMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeGetAdminSettings, ID: "r"}},
		protocol.MsgTypeUpdateAdminSetting:          protocol.UpdateAdminSettingMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeUpdateAdminSetting, ID: "r"}},
		protocol.MsgTypeGetPolicy:                   protocol.GetPolicyMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeGetPolicy, ID: "r"}},
		protocol.MsgTypeGetPolicyDocument:           protocol.GetPolicyDocumentMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeGetPolicyDocument, ID: "r"}},
		protocol.MsgTypeGetPolicyContext:            protocol.GetPolicyContextMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeGetPolicyContext, ID: "r"}},
		protocol.MsgTypeCheckPolicy:                 protocol.CheckPolicyMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeCheckPolicy, ID: "r"}},
		protocol.MsgTypeApplyPolicy:                 protocol.ApplyPolicyMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeApplyPolicy, ID: "r"}},
		protocol.MsgTypeListASASet:                  protocol.ListASASetMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListASASet, ID: "r"}},
		protocol.MsgTypeLookupASA:                   protocol.LookupASAMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeLookupASA, ID: "r"}},
		protocol.MsgTypeAddASA:                      protocol.AddASAMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAddASA, ID: "r"}},
		protocol.MsgTypeRemoveASA:                   protocol.RemoveASAMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRemoveASA, ID: "r"}},
		protocol.MsgTypeSourceTokenSet:              protocol.SourceTokenSetMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSourceTokenSet, ID: "r"}},
		protocol.MsgTypeSourceTokenRemove:           protocol.SourceTokenRemoveMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSourceTokenRemove, ID: "r"}},
		protocol.MsgTypeSourceTokenList:             protocol.SourceTokenListMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSourceTokenList, ID: "r"}},
		protocol.MsgTypeListCosignerReferences:      protocol.ListCosignerReferencesMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListCosignerReferences, ID: "r"}},
		protocol.MsgTypeGetCosignerReference:        protocol.GetCosignerReferenceMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeGetCosignerReference, ID: "r"}},
		protocol.MsgTypeImportCosignerReference:     protocol.ImportCosignerReferenceMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeImportCosignerReference, ID: "r"}},
		protocol.MsgTypeRemoveCosignerReference:     protocol.RemoveCosignerReferenceMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRemoveCosignerReference, ID: "r"}},
		protocol.MsgTypeExportCosignerPublic:        protocol.ExportCosignerPublicMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeExportCosignerPublic, ID: "r"}},
		protocol.MsgTypeListGenerations:             protocol.ListGenerationsMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListGenerations, ID: "r"}},
		protocol.MsgTypePruneGenerationQuarantine:   protocol.PruneGenerationQuarantineMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypePruneGenerationQuarantine, ID: "r"}},
		protocol.MsgTypeDiscardAbandonedGenerations: protocol.DiscardAbandonedGenerationsMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeDiscardAbandonedGenerations, ID: "r"}},
		protocol.MsgTypeListDeletedArchive:          protocol.ListDeletedArchiveMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListDeletedArchive, ID: "r"}},
		protocol.MsgTypePruneDeletedArchive:         protocol.PruneDeletedArchiveMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypePruneDeletedArchive, ID: "r"}},
		protocol.MsgTypeListKeys:                    protocol.ListKeysMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListKeys, ID: "r"}},
		protocol.MsgTypeGetKeyDetails:               protocol.GetKeyDetailsMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeGetKeyDetails, ID: "r"}},
		protocol.MsgTypePrepareGenerateKey:          protocol.PrepareGenerateKeyMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypePrepareGenerateKey, ID: "r"}},
		protocol.MsgTypeGenerateKey:                 protocol.GenerateKeyMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeGenerateKey, ID: "r"}},
		protocol.MsgTypeDeleteKey:                   protocol.DeleteKeyMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeDeleteKey, ID: "r"}},
		protocol.MsgTypeExportKey:                   protocol.ExportKeyMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeExportKey, ID: "r"}},
		protocol.MsgTypeImportKey:                   protocol.ImportKeyMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeImportKey, ID: "r"}},
		protocol.MsgTypeListLibraryTemplates:        protocol.ListLibraryTemplatesMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListLibraryTemplates, ID: "r"}},
		protocol.MsgTypeInstallLibraryTemplate:      protocol.InstallLibraryTemplateMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeInstallLibraryTemplate, ID: "r"}},
		protocol.MsgTypeListInstalledTemplates:      protocol.ListInstalledTemplatesMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListInstalledTemplates, ID: "r"}},
		protocol.MsgTypeShowInstalledTemplate:       protocol.ShowInstalledTemplateMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeShowInstalledTemplate, ID: "r"}},
		protocol.MsgTypeShowLibraryTemplate:         protocol.ShowLibraryTemplateMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeShowLibraryTemplate, ID: "r"}},
		protocol.MsgTypeImportInstalledTemplate:     protocol.ImportInstalledTemplateMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeImportInstalledTemplate, ID: "r"}},
		protocol.MsgTypeRemoveInstalledTemplate:     protocol.RemoveInstalledTemplateMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRemoveInstalledTemplate, ID: "r"}},
		protocol.MsgTypeActivateKeyType:             protocol.ActivateKeyTypeMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeActivateKeyType, ID: "r"}},
		protocol.MsgTypeDeactivateKeyType:           protocol.DeactivateKeyTypeMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeDeactivateKeyType, ID: "r"}},
		protocol.MsgTypeListKeyTypes:                protocol.ListKeyTypesMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListKeyTypes, ID: "r"}},
		protocol.MsgTypeSignResponse:                protocol.SignResponseMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSignResponse, ID: "r"}},
	}
}

func newStrictDecodeTestSession(t *testing.T) (*Session, *queueConn, *stubServices) {
	t.Helper()
	ir := productruntime.New(productruntime.Config{})
	ir.SetUnlocked()
	svc := &stubServices{runtime: ir}
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{
		Product: svc, Settings: svc, Keys: svc, Backups: svc, Templates: svc,
		Inspection: &inspectionStub{}, Authorizer: &recordingAuthorizer{}, Audit: &mutationAudit{},
	}, OriginLocal)
	session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)
	return session, conn, svc
}

func injectTopLevelField(t *testing.T, raw []byte, fieldJSON string) []byte {
	t.Helper()
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		t.Fatalf("expected JSON object, got %q", raw)
	}
	out := make([]byte, 0, len(trimmed)+1+len(fieldJSON))
	out = append(out, trimmed[:len(trimmed)-1]...)
	if len(trimmed) > 2 {
		out = append(out, ',')
	}
	out = append(out, fieldJSON...)
	out = append(out, '}')
	return out
}

func populateRequestSample(sample any) any {
	val := reflect.New(reflect.TypeOf(sample)).Elem()
	val.Set(reflect.ValueOf(sample))
	populateValue(val, 0)
	return val.Interface()
}

func populateValue(v reflect.Value, depth int) {
	if !v.CanSet() || depth > 8 {
		return
	}
	switch v.Kind() {
	case reflect.Struct:
		if v.Type() == reflect.TypeFor[protocol.BaseMessage]() {
			return
		}
		if v.Type() == reflect.TypeFor[time.Time]() {
			v.Set(reflect.ValueOf(time.Unix(1700000000, 0).UTC()))
			return
		}
		for i := range v.NumField() {
			populateValue(v.Field(i), depth+1)
		}
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(1)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1.5)
	case reflect.Slice:
		if v.Type() == reflect.TypeFor[protocol.SensitiveBytes]() {
			v.Set(reflect.ValueOf(protocol.NewSensitiveBytes("secret")))
			return
		}
		if v.Type() == reflect.TypeFor[json.RawMessage]() {
			v.Set(reflect.ValueOf(json.RawMessage(`{"k":"v"}`)))
			return
		}
		if v.Type().Elem().Kind() == reflect.Uint8 {
			v.SetBytes([]byte("x"))
			return
		}
		s := reflect.MakeSlice(v.Type(), 1, 1)
		populateValue(s.Index(0), depth+1)
		v.Set(s)
	case reflect.Array:
		for i := range v.Len() {
			populateValue(v.Index(i), depth+1)
		}
	case reflect.Pointer:
		p := reflect.New(v.Type().Elem())
		populateValue(p.Elem(), depth+1)
		v.Set(p)
	case reflect.Map:
		m := reflect.MakeMapWithSize(v.Type(), 1)
		k := reflect.New(v.Type().Key()).Elem()
		populateValue(k, depth+1)
		elem := reflect.New(v.Type().Elem()).Elem()
		populateValue(elem, depth+1)
		m.SetMapIndex(k, elem)
		v.Set(m)
	case reflect.Interface:
		if v.NumMethod() == 0 {
			v.Set(reflect.ValueOf("x"))
		}
	}
}

// Every request type in dispatchTable (plus auth and initialize_store) must
// round-trip cleanly with all fields populated under strict decoding, and
// reject an unknown field with ErrCodeInvalidRequest.
func TestDispatchTableStrictDecodeRoundTripAndUnknownFieldRefusal(t *testing.T) {
	samples := allDispatchRequestSamples()
	if len(samples) != len(dispatchTable) {
		t.Fatalf("sample count = %d, dispatchTable count = %d; keep samples in sync", len(samples), len(dispatchTable))
	}
	for msgType := range dispatchTable {
		sample, ok := samples[msgType]
		if !ok {
			t.Fatalf("dispatchTable entry %q missing from allDispatchRequestSamples", msgType)
		}
		t.Run(msgType, func(t *testing.T) {
			populated := populateRequestSample(sample)
			raw, err := protocol.MarshalAdminMessage(populated)
			if err != nil {
				t.Fatalf("MarshalAdminMessage(%s) error = %v", msgType, err)
			}

			// Valid marshaled frame with every field populated must decode
			// without ErrCodeInvalidRequest.
			session, conn, _ := newStrictDecodeTestSession(t)
			session.Dispatch(raw)
			for _, w := range decodeAdminProtoWrites(t, conn) {
				if w.Type == protocol.MsgTypeError && w.Code == protocol.ErrCodeInvalidRequest {
					t.Fatalf("Dispatch(%s) valid frame rejected as invalid_request: %+v", msgType, w)
				}
			}

			// Unknown top-level field must be rejected with ErrCodeInvalidRequest.
			withUnknown := injectTopLevelField(t, raw, `"unknown_field":true`)
			session, conn, _ = newStrictDecodeTestSession(t)
			session.Dispatch(withUnknown)
			if len(conn.writes) != 1 {
				t.Fatalf("Dispatch(%s unknown field) writes = %d, want 1", msgType, len(conn.writes))
			}
			var errResp protocol.ErrorMessage
			if err := json.Unmarshal(conn.writes[0], &errResp); err != nil {
				t.Fatalf("unmarshal error response: %v", err)
			}
			if errResp.Code != protocol.ErrCodeInvalidRequest {
				t.Fatalf("Dispatch(%s unknown field) code = %q, want %q", msgType, errResp.Code, protocol.ErrCodeInvalidRequest)
			}
		})
	}

	t.Run("auth_populated", func(t *testing.T) {
		sample := populateRequestSample(protocol.AuthMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAuth, ID: "a"},
		}).(protocol.AuthMessage)
		sample.ProtocolVersion = protocol.AdminProtocolVersion
		raw, err := protocol.MarshalAdminMessage(sample)
		if err != nil {
			t.Fatalf("MarshalAdminMessage(auth) error = %v", err)
		}
		decoded, err := decodeRequest[protocol.AuthMessage](raw)
		defer decoded.Passphrase.Zero()
		if err != nil {
			t.Fatalf("decodeRequest(auth) error = %v", err)
		}
	})

	t.Run("initialize_store_populated", func(t *testing.T) {
		sample := populateRequestSample(protocol.InitializeStoreMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeInitializeStore, ID: "i"},
		}).(protocol.InitializeStoreMessage)
		raw, err := protocol.MarshalAdminMessage(sample)
		if err != nil {
			t.Fatalf("MarshalAdminMessage(initialize_store) error = %v", err)
		}
		decoded, err := decodeRequest[protocol.InitializeStoreMessage](raw)
		defer decoded.Passphrase.Zero()
		if err != nil {
			t.Fatalf("decodeRequest(initialize_store) error = %v", err)
		}
	})
}

// A misspelled review field on generate_key must be refused at decode time
// rather than leaving ReviewedValues empty and skipping the review check.
func TestGenerateKeyRefusesMisspelledReviewFields(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame string
	}{
		{
			name:  "misspelled expected_fingerprint",
			frame: `{"kind":"request","type":"generate_key","id":"g1","key_type":"ed25519","expected_fingerprnt":"abc"}`,
		},
		{
			name:  "misspelled expected_boundary_digest",
			frame: `{"kind":"request","type":"generate_key","id":"g2","key_type":"ed25519","expected_boundary_digst":"def"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, conn, svc := newStrictDecodeTestSession(t)
			session.Dispatch([]byte(tc.frame))
			if svc.generateKeyCalls != 0 {
				t.Fatalf("GenerateKey called %d times, want 0", svc.generateKeyCalls)
			}
			if len(conn.writes) != 1 {
				t.Fatalf("writes = %d, want 1", len(conn.writes))
			}
			var errResp protocol.ErrorMessage
			if err := json.Unmarshal(conn.writes[0], &errResp); err != nil {
				t.Fatalf("unmarshal error response: %v", err)
			}
			if errResp.Code != protocol.ErrCodeInvalidRequest {
				t.Fatalf("code = %q, want %q", errResp.Code, protocol.ErrCodeInvalidRequest)
			}
		})
	}
}

// Nested unknown fields inside request payloads must also be rejected before
// reaching the service handler.
func TestDispatchRefusesNestedUnknownFields(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame string
		calls func(*stubServices) int
	}{
		{
			name:  "apply_policy document extra field",
			frame: `{"kind":"request","type":"apply_policy","id":"p1","documents":[{"key":"default","extra":1}]}`,
			calls: func(svc *stubServices) int { return svc.applyPolicyCalls },
		},
		{
			name:  "add_asa confirmed extra field",
			frame: `{"kind":"request","type":"add_asa","id":"a1","confirmed":{"asset_id":1,"bogus":true}}`,
			calls: func(svc *stubServices) int { return svc.addASACalls },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, conn, svc := newStrictDecodeTestSession(t)
			session.Dispatch([]byte(tc.frame))
			if got := tc.calls(svc); got != 0 {
				t.Fatalf("handler called %d times, want 0", got)
			}
			if len(conn.writes) != 1 {
				t.Fatalf("writes = %d, want 1", len(conn.writes))
			}
			var errResp protocol.ErrorMessage
			if err := json.Unmarshal(conn.writes[0], &errResp); err != nil {
				t.Fatalf("unmarshal error response: %v", err)
			}
			if errResp.Code != protocol.ErrCodeInvalidRequest {
				t.Fatalf("code = %q, want %q", errResp.Code, protocol.ErrCodeInvalidRequest)
			}
		})
	}
}

// decodeRequest must reject unknown fields and trailing tokens while zeroing
// any SensitiveBytes already decoded before the failure, and accept harmless
// trailing whitespace.
func TestDecodeRequestStrictUnknownFieldsTrailingDataAndZeroing(t *testing.T) {
	t.Run("unknown field after passphrase zeroes passphrase", func(t *testing.T) {
		raw := []byte(`{"kind":"request","type":"unlock","id":"u1","passphrase":"secret-value","unexpected":true}`)
		msg, err := decodeRequest[protocol.UnlockMessage](raw)
		if err == nil {
			t.Fatal("decodeRequest accepted an unknown field")
		}
		if len(msg.Passphrase) == 0 || !isZeroedFrame(msg.Passphrase) {
			t.Fatalf("partially decoded passphrase left as %q", []byte(msg.Passphrase))
		}
	})

	for _, tc := range []struct {
		name     string
		trailing string
	}{
		{name: "trailing object", trailing: `{}`},
		{name: "trailing number", trailing: ` 123`},
		{name: "trailing null", trailing: ` null`},
		{name: "trailing garbage", trailing: ` garbage`},
	} {
		t.Run(tc.name+" zeroes passphrase", func(t *testing.T) {
			raw := []byte(`{"kind":"request","type":"unlock","id":"u2","passphrase":"secret-value"}` + tc.trailing)
			msg, err := decodeRequest[protocol.UnlockMessage](raw)
			if err == nil {
				t.Fatalf("decodeRequest accepted %s", tc.name)
			}
			if len(msg.Passphrase) == 0 || !isZeroedFrame(msg.Passphrase) {
				t.Fatalf("decoded passphrase left unzeroed on %s: %q", tc.name, []byte(msg.Passphrase))
			}
		})
	}

	t.Run("trailing whitespace is accepted", func(t *testing.T) {
		raw := []byte("{\"kind\":\"request\",\"type\":\"unlock\",\"id\":\"u3\",\"passphrase\":\"secret-value\"} \n\t ")
		msg, err := decodeRequest[protocol.UnlockMessage](raw)
		if err != nil {
			t.Fatalf("decodeRequest(trailing whitespace) error = %v", err)
		}
		defer msg.Passphrase.Zero()
		if string(msg.Passphrase) != "secret-value" {
			t.Fatalf("passphrase = %q, want secret-value", string(msg.Passphrase))
		}
	})

	t.Run("pre-auth initialize_store unknown field zeroes passphrase", func(t *testing.T) {
		var decoded [][]byte
		original := decodeInitializeStore
		decodeInitializeStore = func(raw []byte) (protocol.InitializeStoreMessage, error) {
			msg, err := original(raw)
			decoded = append(decoded, msg.Passphrase)
			return msg, err
		}
		t.Cleanup(func() { decodeInitializeStore = original })

		conn := &queueConn{}
		svc := &stubServices{}
		session := NewSession(conn, SessionDeps{Product: svc}, OriginLocal)
		raw := []byte(`{"kind":"request","type":"initialize_store","id":"init-2","passphrase":"secret-init","extra":1}`)
		if got := session.handlePreAuthInitialize("init-2", raw); got != AuthOutcomeBootstrapHandled {
			t.Fatalf("handlePreAuthInitialize() = %v", got)
		}
		if len(decoded) != 1 || len(decoded[0]) == 0 || !isZeroedFrame(decoded[0]) {
			t.Fatalf("partially decoded initialize passphrase left as %q", decoded)
		}
		var reply protocol.InitializeStoreResultMessage
		if svc.initializeStoreCalls != 0 || len(conn.writes) != 1 || json.Unmarshal(conn.writes[0], &reply) != nil || reply.Code != protocol.ErrCodeInvalidRequest {
			t.Fatalf("initialize_store with unknown field ran %d times, answered %q", svc.initializeStoreCalls, conn.writes)
		}
	})
}
