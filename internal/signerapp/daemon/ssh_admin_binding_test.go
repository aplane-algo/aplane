// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
)

func TestSSHAdminSessionBindsProductRuntimeInDaemon(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	productRuntime := server.productRuntime()
	authLine := `{"kind":"request","type":"auth","passphrase":"` + string(testPassphrase) + `","protocol_version":{"major":6,"minor":0}}` + "\n"
	conn := newIPCMockConn(authLine, "ssh:remote")
	session := adminserver.NewSession(adminproto.NewUnixAdminConn(conn, nil), server.adminSessionDeps())
	session.SetAuthMethod("ssh-passphrase")
	session.SetTransportInfo(adminserver.TransportSSH, "ssh:remote")

	if !session.Authenticate() {
		t.Fatal("Authenticate() = false, want true")
	}
	if session.BoundRuntime() != productRuntime {
		t.Fatal("BoundRuntime() != product runtime")
	}
	if !productRuntime.IsUnlocked() {
		t.Fatal("product runtime was not unlocked")
	}
	sessionCtx := session.SessionContext()
	if sessionCtx.Transport != adminserver.TransportSSH {
		t.Fatalf("SessionContext().Transport = %q, want %q", sessionCtx.Transport, adminserver.TransportSSH)
	}
	if sessionCtx.AuthMethod != "ssh-passphrase" {
		t.Fatalf("SessionContext().AuthMethod = %q, want ssh-passphrase", sessionCtx.AuthMethod)
	}

	msgs := parseJSONLines(t, conn.writes.Bytes())
	if len(msgs) != 2 {
		t.Fatalf("message count = %d, want 2", len(msgs))
	}
	if !reflectJSONSubset(msgs[1], map[string]any{
		"kind":    string(protocol.MessageKindResponse),
		"type":    protocol.MsgTypeAuthResult,
		"success": true,
	}) {
		t.Fatalf("auth_result shape mismatch: %#v", msgs[1])
	}
}

func TestSSHAdminSessionRejectsUnknownAuthFieldInDaemon(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	productRuntime := server.productRuntime()
	productRuntime.Lock()
	authLine := `{"kind":"request","type":"auth","unexpected_selector":"other","passphrase":"` + string(testPassphrase) + `","protocol_version":{"major":6,"minor":0}}` + "\n"
	conn := newIPCMockConn(authLine, "ssh:remote")
	session := adminserver.NewSession(adminproto.NewUnixAdminConn(conn, nil), server.adminSessionDeps())
	session.SetAuthMethod("ssh-passphrase")
	session.SetTransportInfo(adminserver.TransportSSH, "ssh:remote")

	if session.Authenticate() {
		t.Fatal("Authenticate() = true, want false")
	}
	if productRuntime.IsUnlocked() {
		t.Fatal("product runtime was unlocked after unknown-field rejection")
	}
	if session.BoundRuntime() != nil {
		t.Fatal("BoundRuntime() != nil after rejected SSH auth message")
	}

	msgs := parseJSONLines(t, conn.writes.Bytes())
	if len(msgs) != 2 {
		t.Fatalf("message count = %d, want 2", len(msgs))
	}
	if !reflectJSONSubset(msgs[1], map[string]any{
		"kind":    string(protocol.MessageKindResponse),
		"type":    protocol.MsgTypeAuthResult,
		"success": false,
		"code":    protocol.ErrCodeInvalidAuthMessage,
	}) {
		t.Fatalf("auth_result shape mismatch: %#v", msgs[1])
	}
}
