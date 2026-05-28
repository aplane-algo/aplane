// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminproto

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
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

func TestSessionRejectsExportOnAnyAdminTransport(t *testing.T) {
	for _, transport := range []string{TransportIPC, TransportSSH, TransportUnknown} {
		t.Run(transport, func(t *testing.T) {
			session, conn, _ := newKeyTransportTestSession(transport)

			session.HandleExportKey(&protocol.ExportKeyMessage{
				BaseMessage: protocol.BaseMessage{ID: "export", Type: protocol.MsgTypeExportKey},
				Address:     "ADDR",
				Passphrase:  protocol.NewSensitiveBytes("passphrase"),
			})

			msg := decodeProtocolError(t, conn)
			if msg.Code != protocol.ErrCodeAuthorizationDenied {
				t.Fatalf("error code = %q, want %q", msg.Code, protocol.ErrCodeAuthorizationDenied)
			}
			if !strings.Contains(msg.Error, "key export is disabled") {
				t.Fatalf("error = %q, want export disabled guidance", msg.Error)
			}
		})
	}
}

func TestSessionOmitsGeneratedMnemonicOnEveryAdminTransport(t *testing.T) {
	for _, transport := range []string{TransportIPC, TransportSSH, TransportUnknown} {
		t.Run(transport, func(t *testing.T) {
			session, conn, svc := newKeyTransportTestSession(transport)
			svc.generateKeyResult = GenerateKeyResult{
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
	svc.generateKeyResult = GenerateKeyResult{
		Success: true,
		Address: "ADDR",
		KeyType: "ed25519",
	}
	svc.importKeyResult = ImportKeyResult{
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
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})
	ir.SetUnlocked()
	conn := &queueConn{}
	svc := &stubServices{}
	session := NewSession(conn, SessionDeps{Keys: svc})
	session.SetTransportInfo(transport, "remote")
	session.Bind(auth.NewDefaultIdentity("test"), ir)
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
