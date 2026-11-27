// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"bytes"
	"encoding/json"
	"github.com/aplane-algo/aplane/internal/adminproto"
	"slices"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

func TestSessionGeneratesAndImports(t *testing.T) {
	session, conn, svc := newKeyTransportTestSession()
	svc.generateKeyResult = adminproto.GenerateKeyResult{
		Success: true,
		Address: "ADDR",
		KeyType: "ed25519",
	}
	svc.importKeyResult = adminproto.ImportKeyResult{
		Success: true,
		Address: "ADDR",
		KeyType: "ed25519",
	}

	session.HandleGenerateKey(&protocol.GenerateKeyMessage{
		BaseMessage: protocol.BaseMessage{ID: "generate-ipc", Type: protocol.MsgTypeGenerateKey},
		KeyType:     "ed25519",
	})
	session.HandleImportKey(&protocol.ImportKeyMessage{
		BaseMessage: protocol.BaseMessage{ID: "import-ipc", Type: protocol.MsgTypeImportKey},
		KeyType:     "ed25519",
		Mnemonic:    protocol.NewSensitiveBytes("mnemonic words"),
	})

	if svc.generateKeyCalls != 1 || svc.importKeyCalls != 1 {
		t.Fatalf("key service calls = generate %d import %d, want 1 each", svc.generateKeyCalls, svc.importKeyCalls)
	}
	if svc.lastGenerateKey.KeyType != "ed25519" {
		t.Fatalf("generate request = %+v, want key type", svc.lastGenerateKey)
	}
	if svc.lastGenerateKeyContext == nil {
		t.Fatal("generate key did not receive session context")
	}
	select {
	case <-svc.lastGenerateKeyContext.Done():
		t.Fatal("generate key context canceled before session close")
	default:
	}
	if svc.lastImportKey.KeyType != "ed25519" || string(svc.lastImportMnemonic) != "mnemonic words" {
		t.Fatalf("import request = %+v, want key type and mnemonic", svc.lastImportKey)
	}
	if len(conn.writes) != 2 {
		t.Fatalf("write count = %d, want 2", len(conn.writes))
	}
	var generateMsg protocol.GenerateResultMessage
	if err := json.Unmarshal(conn.writes[0], &generateMsg); err != nil {
		t.Fatalf("decode generate response: %v", err)
	}
	if !generateMsg.Success || generateMsg.Address != "ADDR" || generateMsg.KeyType != "ed25519" {
		t.Fatalf("generate response = %+v, want success with address and key type", generateMsg)
	}
	var importMsg protocol.ImportResultMessage
	if err := json.Unmarshal(conn.writes[1], &importMsg); err != nil {
		t.Fatalf("decode import response: %v", err)
	}
	if !importMsg.Success || importMsg.Address != "ADDR" {
		t.Fatalf("import response = %+v, want success with address", importMsg)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-svc.lastGenerateKeyContext.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("generate key context was not canceled after session close")
	}
}

func newKeyTransportTestSession() (*Session, *queueConn, *stubServices) {
	return newKeyTransportTestSessionAt(OriginLocal)
}

func newKeyTransportTestSessionAt(origin Origin) (*Session, *queueConn, *stubServices) {
	ir := productruntime.New(productruntime.Config{})
	ir.SetUnlocked()
	conn := &queueConn{}
	svc := &stubServices{}
	session := NewSession(conn, SessionDeps{Keys: svc, Audit: &stubAudit{}}, origin)
	session.Bind(auth.NewProductIdentity("test"), ir)
	return session, conn, svc
}

func decodeProtocolError(t *testing.T, conn *queueConn) protocol.ErrorMessage {
	t.Helper()
	var msg protocol.ErrorMessage
	decodeOnlyMessage(t, conn, &msg)
	if msg.Type != protocol.MsgTypeError {
		t.Fatalf("message type = %q, want %q", msg.Type, protocol.MsgTypeError)
	}
	return msg
}

func decodeOnlyMessage(t *testing.T, conn *queueConn, out any) {
	t.Helper()
	if len(conn.writes) != 1 {
		t.Fatalf("write count = %d, want 1", len(conn.writes))
	}
	if err := json.Unmarshal(conn.writes[0], out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func TestSessionExportClearsBuffers(t *testing.T) {
	session, conn, svc := newKeyTransportTestSession()
	words := protocol.NewSensitiveBytes("test recovery material")
	pass := protocol.NewSensitiveBytes("passphrase")
	svc.exportResult = adminproto.ExportKeyResult{Success: true, Address: "ADDR", KeyType: "ed25519", Mnemonic: words, WordCount: 25}
	session.HandleExportKey(&protocol.ExportKeyMessage{BaseMessage: protocol.BaseMessage{ID: "export"}, Address: "ADDR", Passphrase: pass})
	var reply protocol.ExportResultMessage
	decodeOnlyMessage(t, conn, &reply)
	defer reply.Mnemonic.Zero()
	if svc.exportCalls != 1 || !reply.Success || string(reply.Mnemonic) != "test recovery material" {
		t.Fatal("export not delivered")
	}
	if !bytes.Equal(words, make([]byte, len(words))) || !bytes.Equal(pass, make([]byte, len(pass))) {
		t.Fatal("server retained export buffers")
	}
}

func TestSessionExportSendsUndeliveredFailure(t *testing.T) {
	session, conn, svc := newKeyTransportTestSession()
	svc.exportResult = adminproto.ExportKeyResult{Address: "ADDR", Code: "invalid_passphrase", Error: "incorrect passphrase"}
	session.HandleExportKey(&protocol.ExportKeyMessage{BaseMessage: protocol.BaseMessage{ID: "export"}, Address: "ADDR", Passphrase: protocol.NewSensitiveBytes("wrong")})
	var reply protocol.ExportResultMessage
	decodeOnlyMessage(t, conn, &reply)
	if reply.Success || reply.ID != "export" || reply.Code != "invalid_passphrase" || len(reply.Mnemonic) != 0 {
		t.Fatalf("failure reply = %+v", reply)
	}
}

func TestPrepareGenerateKeyOverIPC(t *testing.T) {
	session, conn, svc := newKeyTransportTestSession()
	svc.prepareGenerateResult = adminproto.PrepareGenerateKeyResult{
		Success: true, KeyType: "test.bounded.v1", Fingerprint: "1:abc", CosignerKeyID: "COSIGNER",
		Host: &adminproto.PreparedHostProfile{
			Rekey: "refused", CosignerRequired: true,
			Bounds: &adminproto.PreparedHostBounds{SpendEffects: []string{"pay"}, MaxFee: 10_000, Layer3Policy: "merkle_allowlist"},
		},
	}
	session.HandlePrepareGenerateKey(&protocol.PrepareGenerateKeyMessage{
		BaseMessage: protocol.BaseMessage{ID: "prepare-ipc", Type: protocol.MsgTypePrepareGenerateKey},
		KeyType:     "test.bounded.v1",
		Parameters:  map[string]string{"cosigner": "ops"},
	})
	if svc.prepareGenerateCalls != 1 || svc.lastPrepareGenerate.Parameters["cosigner"] != "ops" {
		t.Fatalf("prepare calls = %d request = %+v", svc.prepareGenerateCalls, svc.lastPrepareGenerate)
	}
	var msg protocol.PrepareGenerateResultMessage
	decodeOnlyMessage(t, conn, &msg)
	if !msg.Success || msg.Type != protocol.MsgTypePrepareGenerateResult || msg.ID != "prepare-ipc" || msg.Fingerprint != "1:abc" || msg.CosignerKeyID != "COSIGNER" {
		t.Fatalf("response = %+v", msg)
	}
	if msg.Host == nil || !msg.Host.CosignerRequired ||
		msg.Host.Rekey != "refused" || msg.Host.Bounds == nil || msg.Host.Bounds.Layer3Policy != "merkle_allowlist" ||
		msg.Host.Bounds.MaxFee != 10_000 || !slices.Equal(msg.Host.Bounds.SpendEffects, []string{"pay"}) {
		t.Fatalf("host = %+v", msg.Host)
	}
}

func TestGenerateKeyPassesTheExpectedFingerprint(t *testing.T) {
	session, conn, svc := newKeyTransportTestSession()
	svc.generateKeyResult = adminproto.GenerateKeyResult{Success: true, Address: "ADDR", KeyType: "ed25519"}
	session.HandleGenerateKey(&protocol.GenerateKeyMessage{
		BaseMessage:         protocol.BaseMessage{ID: "generate-reviewed", Type: protocol.MsgTypeGenerateKey},
		KeyType:             "ed25519",
		ExpectedFingerprint: "1:abc",
	})
	if svc.lastGenerateKey.ExpectedFingerprint != "1:abc" {
		t.Fatalf("generate request = %+v", svc.lastGenerateKey)
	}
	var msg protocol.GenerateResultMessage
	decodeOnlyMessage(t, conn, &msg)
}

// Operations that move recovery material or prepare a key run only on the
// local socket. A remote session, or one whose server never stated an origin,
// is refused before the service is called.
func TestNonLocalSessionRefusesRecoveryMaterialOperations(t *testing.T) {
	for _, origin := range []Origin{OriginRemote, Origin(0)} {
		t.Run(origin.AuditTransport(), func(t *testing.T) {
			ops := []struct {
				name  string
				run   func(*Session)
				calls func(*stubServices) int
			}{
				{"import", func(s *Session) {
					s.HandleImportKey(&protocol.ImportKeyMessage{BaseMessage: protocol.BaseMessage{ID: "import"}, KeyType: "ed25519", Mnemonic: protocol.NewSensitiveBytes("mnemonic words")})
				}, func(s *stubServices) int { return s.importKeyCalls }},
				{"export", func(s *Session) {
					s.HandleExportKey(&protocol.ExportKeyMessage{BaseMessage: protocol.BaseMessage{ID: "export"}, Address: "ADDR", Passphrase: protocol.NewSensitiveBytes("passphrase")})
				}, func(s *stubServices) int { return s.exportCalls }},
				{"prepare_generate", func(s *Session) {
					s.HandlePrepareGenerateKey(&protocol.PrepareGenerateKeyMessage{BaseMessage: protocol.BaseMessage{ID: "prepare"}, KeyType: "ed25519"})
				}, func(s *stubServices) int { return s.prepareGenerateCalls }},
			}
			for _, op := range ops {
				session, conn, svc := newKeyTransportTestSessionAt(origin)
				op.run(session)
				if n := op.calls(svc); n != 0 {
					t.Fatalf("%s: service calls = %d, want 0", op.name, n)
				}
				if msg := decodeProtocolError(t, conn); msg.Code != protocol.ErrCodeAuthorizationDenied {
					t.Fatalf("%s: error code = %q, want %q", op.name, msg.Code, protocol.ErrCodeAuthorizationDenied)
				}
			}
		})
	}
}

// The import handler zeroes the recovery phrase it decoded once the import
// returns, and also when it refuses the request before calling the service.
func TestSessionImportZeroesMnemonicAfterUse(t *testing.T) {
	session, _, svc := newKeyTransportTestSession()
	svc.importKeyResult = adminproto.ImportKeyResult{Success: true, Address: "ADDR", KeyType: "ed25519"}
	msg := &protocol.ImportKeyMessage{
		BaseMessage: protocol.BaseMessage{ID: "import-zero", Type: protocol.MsgTypeImportKey},
		KeyType:     "ed25519",
		Mnemonic:    protocol.NewSensitiveBytes("mnemonic words"),
	}
	session.HandleImportKey(msg)
	if svc.importKeyCalls != 1 || string(svc.lastImportMnemonic) != "mnemonic words" {
		t.Fatalf("service saw %d imports with phrase %q", svc.importKeyCalls, svc.lastImportMnemonic)
	}
	if !bytes.Equal(svc.lastImportKey.Mnemonic, make([]byte, len("mnemonic words"))) {
		t.Fatalf("phrase left as %q after the import", svc.lastImportKey.Mnemonic)
	}

	refusing, _, refusingSvc := newKeyTransportTestSessionAt(OriginRemote)
	refused := &protocol.ImportKeyMessage{
		BaseMessage: protocol.BaseMessage{ID: "import-refused", Type: protocol.MsgTypeImportKey},
		KeyType:     "ed25519",
		Mnemonic:    protocol.NewSensitiveBytes("mnemonic words"),
	}
	refusing.HandleImportKey(refused)
	if refusingSvc.importKeyCalls != 0 {
		t.Fatal("a remote session reached the import service")
	}
	if !bytes.Equal(refused.Mnemonic, make([]byte, len("mnemonic words"))) {
		t.Fatalf("refused import left the phrase as %q", []byte(refused.Mnemonic))
	}
}
