// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
)

const testLoginTimeout = 300 * time.Millisecond

func newLoginTimeoutTestServer(t *testing.T) *IPCServer {
	t.Helper()
	signer, cleanup := setupTestSigner(t)
	t.Cleanup(cleanup)
	server := &IPCServer{
		signer:         signer,
		manager:        adminserver.NewSessionManager(),
		preAuthTimeout: testLoginTimeout,
	}
	signer.ipcServer = server
	return server
}

// startAdminConn runs one accepted connection and returns the client side
// plus a channel closed when the server finishes with it.
func startAdminConn(t *testing.T, server *IPCServer) (net.Conn, *bufio.Reader, <-chan struct{}) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.acceptAdminSession(
			adminproto.NewUnixAdminConn(serverConn, nil),
			adminserver.TransportIPC,
			"ipc-passphrase",
		)
	}()
	return clientConn, bufio.NewReader(clientConn), done
}

func waitDone(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(ipcDisconnectTestTimeout):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// A client left at the login screen once held the single pre-auth slot
// forever, so no other apadmin could connect. The login deadline ends it,
// tells it why, and frees the slot.
func TestPreAuthLoginTimeoutFreesTheLoginSlot(t *testing.T) {
	server := newLoginTimeoutTestServer(t)

	idleConn, idleReader, idleDone := startAdminConn(t, server)
	readAdminMessageType(t, idleConn, idleReader, protocol.MsgTypeAuthRequired)

	// While the idle client waits, a second client is turned away.
	blockedConn, blockedReader, blockedDone := startAdminConn(t, server)
	rawErr := readAdminMessageType(t, blockedConn, blockedReader, protocol.MsgTypeError)
	if !strings.Contains(string(rawErr), "currently authenticating") {
		t.Fatalf("second client error = %s, want the login slot to be busy", rawErr)
	}
	waitDone(t, blockedDone, "the rejected client")

	rawResult := readAdminMessageType(t, idleConn, idleReader, protocol.MsgTypeAuthResult)
	var result protocol.AuthResultMessage
	if err := json.Unmarshal(rawResult, &result); err != nil {
		t.Fatalf("decode auth_result: %v", err)
	}
	if result.Success || result.Code != protocol.ErrCodeLoginTimeout {
		t.Fatalf("auth_result = %+v, want a login_timeout failure", result)
	}
	waitDone(t, idleDone, "the timed-out client")

	nextConn, nextReader, _ := startAdminConn(t, server)
	readAdminMessageType(t, nextConn, nextReader, protocol.MsgTypeAuthRequired)
}

// The deadline covers only the login. An authenticated session keeps
// running after it would have passed.
func TestPreAuthLoginTimeoutIsClearedAfterLogin(t *testing.T) {
	server := newLoginTimeoutTestServer(t)
	server.signer.productRuntime().Config().SetLockOnDisconnect(false)

	conn, reader, done := startAdminConn(t, server)
	readAdminMessageType(t, conn, reader, protocol.MsgTypeAuthRequired)
	writeAdminMessage(t, conn, protocol.AuthMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeAuth,
		},
		Passphrase:      protocol.NewSensitiveBytes(string(testPassphrase)),
		ProtocolVersion: testAdminProtocolVersion(),
	})
	rawResult := readAdminMessageType(t, conn, reader, protocol.MsgTypeAuthResult)
	var result protocol.AuthResultMessage
	if err := json.Unmarshal(rawResult, &result); err != nil {
		t.Fatalf("decode auth_result: %v", err)
	}
	if !result.Success {
		t.Fatalf("auth_result = %+v, want success", result)
	}

	// Keep draining server pushes so the session is blocked in its read, where
	// a leftover login deadline would end it.
	go func() { _, _ = io.Copy(io.Discard, reader) }()
	time.Sleep(3 * testLoginTimeout)
	select {
	case <-done:
		t.Fatal("authenticated session ended when the login deadline passed")
	default:
	}
	if server.activeSession() == nil {
		t.Fatal("authenticated session is no longer active after the login deadline")
	}

	_ = conn.Close()
	waitDone(t, done, "session cleanup")
}
