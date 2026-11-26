// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"slices"
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

// The lock a disconnect makes is recorded, and only when it locked the signer:
// one the session locked itself before leaving has its own entry.
func TestAdminDisconnectAppliesLockOnDisconnect(t *testing.T) {
	for _, tc := range []struct {
		name             string
		lockOnDisconnect bool
		lockFirst        bool
		wantUnlocked     bool
		wantLocks        []string // the IDENTITY_LOCKED reasons
	}{
		{
			name:             "true locks signer",
			lockOnDisconnect: true,
			wantUnlocked:     false,
			wantLocks:        []string{autoLockReason},
		},
		{
			name:             "false leaves signer unlocked",
			lockOnDisconnect: false,
			wantUnlocked:     true,
		},
		{
			name:             "true after the session locked",
			lockOnDisconnect: true,
			lockFirst:        true,
			wantUnlocked:     false,
			wantLocks:        []string{"operator"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer, cleanup := setupTestSigner(t)
			defer cleanup()
			auditPath := useTestAuditLog(t, signer)

			ir := signer.productRuntime()
			ir.SetUnlocked()
			ir.Config().SetLockOnDisconnect(tc.lockOnDisconnect)

			ipcServer := &IPCServer{
				signer:  signer,
				manager: adminserver.NewSessionManager(),
			}
			signer.ipcServer = ipcServer
			signer.hub = signer.ipcServer

			serverConn, clientConn := net.Pipe()
			defer func() { _ = clientConn.Close() }()

			done := make(chan struct{})
			go func() {
				defer close(done)
				ipcServer.acceptAdminSession(
					adminproto.NewUnixAdminConn(serverConn),
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
				ProtocolVersion: protocol.AdminProtocolVersion,
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
			if tc.lockFirst {
				writeAdminMessage(t, clientConn, protocol.LockIdentityMessage{
					BaseMessage: protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeLockIdentity, ID: "lock-1"},
					Reason:      "operator",
				})
				readAdminMessageType(t, clientConn, reader, protocol.MsgTypeLockIdentityResult)
			}

			_ = clientConn.Close()
			select {
			case <-done:
			case <-time.After(ipcDisconnectTestTimeout):
				t.Fatal("timed out waiting for admin session cleanup")
			}

			if got := ir.IsUnlocked(); got != tc.wantUnlocked {
				t.Fatalf("IsUnlocked() = %v, want %v", got, tc.wantUnlocked)
			}
			var locks []string
			for _, entry := range auditEntries(t, auditPath, "IDENTITY_LOCKED") {
				locks = append(locks, entry["reason"].(string))
				if entry["principal"] == nil {
					t.Errorf("IDENTITY_LOCKED names no principal: %v", entry)
				}
			}
			if !slices.Equal(locks, tc.wantLocks) {
				t.Fatalf("IDENTITY_LOCKED reasons = %v, want %v", locks, tc.wantLocks)
			}
			// The owner's session entries carry no reason; an observer's say auth_only.
			for _, entry := range auditEntries(t, auditPath, "SESSION_CONNECTED", "SESSION_DISCONNECTED") {
				if reason, given := entry["reason"]; given {
					t.Errorf("the owner's %v has reason %q", entry["event"], reason)
				}
			}
		})
	}
}

func TestAdminAuthOnlyIsNonOwningAndPreservesActiveSigner(t *testing.T) {
	signer, cleanup := setupTestSigner(t)
	defer cleanup()
	auditPath := useTestAuditLog(t, signer)

	ir := signer.productRuntime()
	ir.SetUnlocked()
	ir.Config().SetLockOnDisconnect(true)

	ipcServer := &IPCServer{
		signer:  signer,
		manager: adminserver.NewSessionManager(),
	}
	signer.ipcServer = ipcServer
	signer.hub = signer.ipcServer

	owner := adminserver.NewSession(adminproto.NewUnixAdminConn(&hubStubConn{}), signer.adminSessionDeps(), adminserver.OriginLocal)
	owner.Bind(auth.NewProductIdentity("test-owner"), ir)
	if !registerPendingSession(ipcServer.manager, owner) {
		t.Fatal("registerPendingSession(owner) = false, want true")
	}
	ipcServer.manager.PromoteToActive(owner)

	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		ipcServer.acceptAdminSession(
			adminproto.NewUnixAdminConn(serverConn),
		)
	}()

	reader := bufio.NewReader(clientConn)
	readAdminMessageType(t, clientConn, reader, protocol.MsgTypeClientExists)
	writeAdminMessage(t, clientConn, protocol.DisplaceConfirmMessage{
		BaseMessage: protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeDisplaceConfirm},
	})
	readAdminMessageType(t, clientConn, reader, protocol.MsgTypeAuthRequired)
	writeAdminMessage(t, clientConn, protocol.AuthMessage{
		BaseMessage:     protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeAuthOnly},
		Passphrase:      protocol.NewSensitiveBytes(string(testPassphrase)),
		ProtocolVersion: protocol.AdminProtocolVersion,
	})
	rawAuth := readAdminMessageType(t, clientConn, reader, protocol.MsgTypeAuthResult)
	var authResult protocol.AuthResultMessage
	if err := json.Unmarshal(rawAuth, &authResult); err != nil {
		t.Fatalf("decode auth_result: %v", err)
	}
	if !authResult.Success {
		t.Fatalf("auth_result success = false: %+v", authResult)
	}
	writeAdminMessage(t, clientConn, protocol.GetAdminSettingsMessage{
		BaseMessage: protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeGetAdminSettings, ID: "read-1"},
	})
	readAdminMessageType(t, clientConn, reader, protocol.MsgTypeAdminSettings)
	writeAdminMessage(t, clientConn, protocol.LockIdentityMessage{
		BaseMessage: protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeLockIdentity, ID: "mutate-1"},
	})
	rawDenied := readAdminMessageType(t, clientConn, reader, protocol.MsgTypeError)
	var denied protocol.ErrorMessage
	if err := json.Unmarshal(rawDenied, &denied); err != nil {
		t.Fatalf("decode auth_only mutation rejection: %v", err)
	}
	if denied.Code != protocol.ErrCodeAuthorizationDenied {
		t.Fatalf("auth_only mutation code = %q, want %q", denied.Code, protocol.ErrCodeAuthorizationDenied)
	}

	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(ipcDisconnectTestTimeout):
		t.Fatal("timed out waiting for auth_only session cleanup")
	}

	if ipcServer.activeSession() != owner {
		t.Fatal("auth_only session displaced the active owner")
	}
	if !ir.IsUnlocked() {
		t.Fatal("auth_only disconnect locked the serving signer")
	}
	// The observer's connection and its end are recorded, as such.
	entries := auditEntries(t, auditPath, "SESSION_CONNECTED", "SESSION_DISCONNECTED", "IDENTITY_LOCKED")
	var got []string
	for _, entry := range entries {
		got = append(got, fmt.Sprintf("%v %v", entry["event"], entry["reason"]))
		if entry["principal"] == nil {
			t.Errorf("%v names no principal: %v", entry["event"], entry)
		}
	}
	if want := []string{"SESSION_CONNECTED auth_only", "SESSION_DISCONNECTED auth_only"}; !slices.Equal(got, want) {
		t.Fatalf("audit = %v, want %v", got, want)
	}
}

func TestAdminAuthPromotionFailureCleansUnlockedIdentity(t *testing.T) {
	signer, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := signer.productRuntime()
	ir.Lock()
	ir.Config().SetLockOnDisconnect(true)

	ipcServer := &IPCServer{
		signer:  signer,
		manager: adminserver.NewSessionManager(),
	}
	signer.ipcServer = ipcServer
	signer.hub = signer.ipcServer

	blocker := adminserver.NewSession(adminproto.NewUnixAdminConn(&hubStubConn{}), signer.adminSessionDeps(), adminserver.OriginLocal)
	if !registerPendingSession(ipcServer.manager, blocker) {
		t.Fatal("registerPendingSession(blocker) = false, want true")
	}

	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		ipcServer.acceptAdminSession(
			adminproto.NewUnixAdminConn(serverConn),
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
		ProtocolVersion: protocol.AdminProtocolVersion,
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
	if ipcServer.sessionManager().HasClient() {
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
