// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
)

// Admin authentication performs passphrase verification and may unlock and
// reload an identity before replying. Leave enough headroom for those
// operations under the race detector and concurrent CI package load.
const ipcDisconnectTestTimeout = 5 * time.Second

func TestAdminDisconnectAppliesLockOnDisconnect(t *testing.T) {
	for _, tc := range []struct {
		name             string
		lockOnDisconnect bool
		wantUnlocked     bool
	}{
		{
			name:             "true locks signer",
			lockOnDisconnect: true,
			wantUnlocked:     false,
		},
		{
			name:             "false leaves signer unlocked",
			lockOnDisconnect: false,
			wantUnlocked:     true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer, cleanup := setupTestSigner(t)
			defer cleanup()

			ir := signer.registry.Get(auth.DefaultIdentityID)
			ir.SetUnlocked()
			ir.Config().SetLockOnDisconnect(tc.lockOnDisconnect)

			ipcServer := &IPCServer{
				signer:  signer,
				manager: adminserver.NewSessionManager(),
			}
			signer.ipcServer = ipcServer

			serverConn, clientConn := net.Pipe()
			defer func() { _ = clientConn.Close() }()

			done := make(chan struct{})
			go func() {
				defer close(done)
				ipcServer.acceptAdminSession(
					adminproto.NewUnixAdminConn(serverConn, nil),
					adminserver.TransportIPC,
					"ipc-passphrase",
					"",
				)
			}()

			reader := bufio.NewReader(clientConn)
			readAdminMessageType(t, clientConn, reader, protocol.MsgTypeAuthRequired)
			writeAdminMessage(t, clientConn, protocol.AuthMessage{
				BaseMessage: protocol.BaseMessage{
					Kind: protocol.MessageKindRequest,
					Type: protocol.MsgTypeAuth,
				},
				Passphrase:      protocol.NewSensitiveBytes(string(testPassphrase)),
				ProtocolVersion: testAdminProtocolVersion(),
			})

			rawAuth := readAdminMessageType(t, clientConn, reader, protocol.MsgTypeAuthResult)
			var authResult protocol.AuthResultMessage
			if err := json.Unmarshal(rawAuth, &authResult); err != nil {
				t.Fatalf("decode auth_result: %v", err)
			}
			if !authResult.Success {
				t.Fatalf("auth_result success = false: %+v", authResult)
			}
			readAdminMessageType(t, clientConn, reader, protocol.MsgTypeStatus)

			_ = clientConn.Close()
			select {
			case <-done:
			case <-time.After(ipcDisconnectTestTimeout):
				t.Fatal("timed out waiting for admin session cleanup")
			}

			if got := ir.IsUnlocked(); got != tc.wantUnlocked {
				t.Fatalf("IsUnlocked() = %v, want %v", got, tc.wantUnlocked)
			}
		})
	}
}

func TestAdminAuthPromotionFailureCleansUnlockedIdentity(t *testing.T) {
	signer, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := signer.registry.Get(auth.DefaultIdentityID)
	ir.Lock()
	ir.Config().SetLockOnDisconnect(true)

	ipcServer := &IPCServer{
		signer:  signer,
		manager: adminserver.NewSessionManager(),
	}
	signer.ipcServer = ipcServer

	blocker := adminserver.NewSession(adminproto.NewUnixAdminConn(&hubStubConn{}, nil), signer.adminSessionDeps())
	if !ipcServer.manager.RegisterPending(auth.DefaultIdentityID, blocker) {
		t.Fatal("RegisterPending(blocker) = false, want true")
	}

	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		ipcServer.acceptAdminSession(
			adminproto.NewUnixAdminConn(serverConn, nil),
			adminserver.TransportIPC,
			"ipc-passphrase",
			"",
		)
	}()

	reader := bufio.NewReader(clientConn)
	readAdminMessageType(t, clientConn, reader, protocol.MsgTypeAuthRequired)
	writeAdminMessage(t, clientConn, protocol.AuthMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeAuth,
		},
		Passphrase:      protocol.NewSensitiveBytes(string(testPassphrase)),
		ProtocolVersion: testAdminProtocolVersion(),
	})

	rawAuth := readAdminMessageType(t, clientConn, reader, protocol.MsgTypeAuthResult)
	var authResult protocol.AuthResultMessage
	if err := json.Unmarshal(rawAuth, &authResult); err != nil {
		t.Fatalf("decode auth_result: %v", err)
	}
	if !authResult.Success {
		t.Fatalf("auth_result success = false: %+v", authResult)
	}

	select {
	case <-done:
	case <-time.After(ipcDisconnectTestTimeout):
		t.Fatal("timed out waiting for admin session cleanup")
	}

	if ir.IsUnlocked() {
		t.Fatal("identity remained unlocked after authenticated session failed promotion")
	}
	if ipcServer.sessionManager().HasClient(auth.DefaultIdentityID) {
		t.Fatal("identity unexpectedly has an active admin client")
	}
}

func readAdminMessageType(t *testing.T, conn net.Conn, reader *bufio.Reader, wantType string) []byte {
	t.Helper()
	for i := 0; i < 5; i++ {
		if err := conn.SetReadDeadline(time.Now().Add(ipcDisconnectTestTimeout)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		line, err := reader.ReadBytes('\n')
		if err != nil {
			t.Fatalf("ReadBytes: %v", err)
		}
		raw := bytes.TrimSpace(line)
		base, err := protocol.ParseAdminBaseMessage(raw)
		if err != nil {
			t.Fatalf("ParseAdminBaseMessage(%q): %v", raw, err)
		}
		if base.Type == wantType {
			return raw
		}
	}
	t.Fatalf("did not receive message type %q", wantType)
	return nil
}

func writeAdminMessage(t *testing.T, conn net.Conn, msg interface{}) {
	t.Helper()
	data, err := protocol.MarshalAdminMessage(msg)
	if err != nil {
		t.Fatalf("MarshalAdminMessage: %v", err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(ipcDisconnectTestTimeout)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		t.Fatalf("Write: %v", err)
	}
}
