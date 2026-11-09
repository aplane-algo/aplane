// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"bytes"
	"encoding/json"
	"github.com/aplane-algo/aplane/internal/adminproto"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

func TestSessionRejectsImportOutsideIPC(t *testing.T) {
	for _, transport := range []string{TransportSSH, TransportUnknown} {
		t.Run(transport, func(t *testing.T) {
			session, conn, svc := newKeyTransportTestSession(transport)

			session.HandleImportKey(&protocol.ImportKeyMessage{
				BaseMessage: protocol.BaseMessage{ID: "import-remote", Type: protocol.MsgTypeImportKey},
				KeyType:     "ed25519",
				Mnemonic:    "mnemonic words",
			})

			if svc.importKeyCalls != 0 {
				t.Fatalf("import calls = %d, want 0", svc.importKeyCalls)
			}
			msg := decodeProtocolError(t, conn)
			if msg.Code != protocol.ErrCodeAuthorizationDenied {
				t.Fatalf("error code = %q, want %q", msg.Code, protocol.ErrCodeAuthorizationDenied)
			}
			if !strings.Contains(msg.Error, "local AP Admin") {
				t.Fatalf("error = %q, want local AP Admin guidance", msg.Error)
			}
		})
	}
}

func TestSessionRejectsExportOutsideIPC(t *testing.T) {
	for _, transport := range []string{TransportSSH, TransportUnknown} {
		t.Run(transport, func(t *testing.T) {
			session, conn, svc := newKeyTransportTestSession(transport)

			session.HandleExportKey(&protocol.ExportKeyMessage{
				BaseMessage: protocol.BaseMessage{ID: "export", Type: protocol.MsgTypeExportKey},
				Address:     "ADDR",
				Passphrase:  protocol.NewSensitiveBytes("passphrase"),
			})

			if svc.exportCalls != 0 {
				t.Fatal("remote export called service")
			}
			msg := decodeProtocolError(t, conn)
			if msg.Code != protocol.ErrCodeAuthorizationDenied {
				t.Fatalf("error code = %q, want %q", msg.Code, protocol.ErrCodeAuthorizationDenied)
			}
			if !strings.Contains(msg.Error, "local AP Admin") {
				t.Fatalf("error = %q, want local IPC guidance", msg.Error)
			}
		})
	}
}

func TestSessionOmitsGeneratedMnemonicOnEveryAdminTransport(t *testing.T) {
	for _, transport := range []string{TransportIPC, TransportSSH, TransportUnknown} {
		t.Run(transport, func(t *testing.T) {
			session, conn, svc := newKeyTransportTestSession(transport)
			svc.generateKeyResult = adminproto.GenerateKeyResult{
				Success: true,
				Address: "ADDR",
				KeyType: "ed25519",
			}

			session.HandleGenerateKey(&protocol.GenerateKeyMessage{
				BaseMessage: protocol.BaseMessage{ID: "generate-remote", Type: protocol.MsgTypeGenerateKey},
				KeyType:     "ed25519",
			})

			if svc.generateKeyCalls != 1 {
				t.Fatalf("generate calls = %d, want 1", svc.generateKeyCalls)
			}
			var msg protocol.GenerateResultMessage
			decodeOnlyMessage(t, conn, &msg)
			if !msg.Success || msg.Address != "ADDR" || msg.KeyType != "ed25519" {
				t.Fatalf("generate response = %+v, want success with address and key type", msg)
			}
			if msg.Mnemonic != "" || msg.WordCount != 0 {
				t.Fatalf("generate response leaked mnemonic fields: %+v", msg)
			}
		})
	}
}

func TestSessionAllowsGenerateAndImportOverIPC(t *testing.T) {
	session, conn, svc := newKeyTransportTestSession(TransportIPC)
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
		Mnemonic:    "mnemonic words",
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
	if svc.lastImportKey.KeyType != "ed25519" || svc.lastImportKey.Mnemonic != "mnemonic words" {
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
	if generateMsg.Mnemonic != "" || generateMsg.WordCount != 0 {
		t.Fatalf("generate response leaked mnemonic fields: %+v", generateMsg)
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

func newKeyTransportTestSession(transport string) (*Session, *queueConn, *stubServices) {
	ir := productruntime.New(productruntime.Config{})
	ir.SetUnlocked()
	conn := &queueConn{}
	svc := &stubServices{}
	session := NewSession(conn, SessionDeps{Keys: svc})
	session.SetTransportInfo(transport, "remote")
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

func TestSessionExportsOnlyOverIPCAndClearsBuffers(t *testing.T) {
	session, conn, svc := newKeyTransportTestSession(TransportIPC)
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
	session, conn, svc := newKeyTransportTestSession(TransportIPC)
	svc.exportResult = adminproto.ExportKeyResult{Address: "ADDR", Code: "invalid_passphrase", Error: "incorrect passphrase"}
	session.HandleExportKey(&protocol.ExportKeyMessage{BaseMessage: protocol.BaseMessage{ID: "export"}, Address: "ADDR", Passphrase: protocol.NewSensitiveBytes("wrong")})
	var reply protocol.ExportResultMessage
	decodeOnlyMessage(t, conn, &reply)
	if reply.Success || reply.ID != "export" || reply.Code != "invalid_passphrase" || len(reply.Mnemonic) != 0 {
		t.Fatalf("failure reply = %+v", reply)
	}
}

func TestPrepareGenerateKeyIsLocalOnly(t *testing.T) {
	for _, transport := range []string{TransportSSH, TransportUnknown} {
		t.Run(transport, func(t *testing.T) {
			session, conn, svc := newKeyTransportTestSession(transport)
			session.HandlePrepareGenerateKey(&protocol.PrepareGenerateKeyMessage{
				BaseMessage: protocol.BaseMessage{ID: "prepare-remote", Type: protocol.MsgTypePrepareGenerateKey},
				KeyType:     "ed25519",
			})
			if svc.prepareGenerateCalls != 0 {
				t.Fatalf("prepare calls = %d, want 0", svc.prepareGenerateCalls)
			}
			msg := decodeProtocolError(t, conn)
			if msg.Code != protocol.ErrCodeAuthorizationDenied || !strings.Contains(msg.Error, "local AP Admin") {
				t.Fatalf("error = %+v, want local IPC guidance", msg)
			}
		})
	}
}

func TestPrepareGenerateKeyOverIPC(t *testing.T) {
	session, conn, svc := newKeyTransportTestSession(TransportIPC)
	svc.prepareGenerateResult = adminproto.PrepareGenerateKeyResult{
		Success: true, KeyType: "test.bounded.v1", Fingerprint: "1:abc", CosignerKeyID: "COSIGNER",
		Bounded: &adminproto.PreparedBoundedProfile{
			Contract: "bounded2", SpendEffects: []string{"pay"}, MaxFee: new(uint64(10_000)), Rekey: "refused", Layer3Policy: "merkle_allowlist", CosignerRequired: true,
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
	if msg.Bounded == nil || !msg.Bounded.CosignerRequired || msg.Bounded.Contract != "bounded2" ||
		msg.Bounded.Rekey != "refused" || msg.Bounded.Layer3Policy != "merkle_allowlist" {
		t.Fatalf("bounded = %+v", msg.Bounded)
	}
}

func TestGenerateKeyPassesTheExpectedFingerprint(t *testing.T) {
	session, conn, svc := newKeyTransportTestSession(TransportIPC)
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
