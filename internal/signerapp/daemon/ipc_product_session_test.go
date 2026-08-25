// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
)

func addActiveProductSession(t *testing.T, server *IPCServer) *ipcJSONRecorderConn {
	t.Helper()
	recorder := &ipcJSONRecorderConn{}
	session := adminserver.NewSession(adminproto.NewUnixAdminConn(recorder, nil), adminserver.SessionDeps{})
	if !server.sessionManager().RegisterPending(session) {
		t.Fatal("RegisterPending() = false, want true")
	}
	if _, ok := server.sessionManager().PromoteToActive(session); !ok {
		t.Fatal("PromoteToActive() = false, want true")
	}
	return recorder
}

func TestIPCSendSignRequestUsesActiveProductSession(t *testing.T) {
	ipcServer := &IPCServer{manager: adminserver.NewSessionManager()}
	recorder := addActiveProductSession(t, ipcServer)
	if !ipcServer.SendSignRequest(&signerapproval.SignRequest{ID: "req-1", Address: "ADDR"}) {
		t.Fatal("SendSignRequest() = false, want true")
	}
	messages := recorder.messages(t)
	if len(messages) != 1 || !reflectJSONSubset(messages[0], map[string]any{
		"kind": string(protocol.MessageKindNotification),
		"type": protocol.MsgTypeSignRequest,
		"id":   "req-1",
	}) {
		t.Fatalf("sign request shape mismatch: %#v", messages)
	}
}

func TestIPCTokenProvisioningUsesActiveProductSession(t *testing.T) {
	ipcServer := &IPCServer{manager: adminserver.NewSessionManager()}
	recorder := addActiveProductSession(t, ipcServer)
	if !ipcServer.SendTokenProvisioningRequest(&signerapproval.TokenProvisioningRequest{ID: "token-1"}) {
		t.Fatal("SendTokenProvisioningRequest() = false, want true")
	}
	messages := recorder.messages(t)
	if len(messages) != 1 || !reflectJSONSubset(messages[0], map[string]any{
		"type": protocol.MsgTypeTokenProvisioningRequest,
		"id":   "token-1",
	}) {
		t.Fatalf("token provisioning shape mismatch: %#v", messages)
	}
}

func TestIPCSendSignRequestCanceledUsesActiveProductSession(t *testing.T) {
	ipcServer := &IPCServer{manager: adminserver.NewSessionManager()}
	recorder := addActiveProductSession(t, ipcServer)
	if !ipcServer.SendSignRequestCanceled(&signerapproval.SignRequestCanceled{
		ID: "req-1", Reason: signerapproval.SignRequestCancelReasonClientCanceled,
	}) {
		t.Fatal("SendSignRequestCanceled() = false, want true")
	}
	messages := recorder.messages(t)
	if len(messages) != 1 || messages[0]["type"] != protocol.MsgTypeSignRequestCanceled {
		t.Fatalf("sign cancellation shape mismatch: %#v", messages)
	}
}

func TestIPCNotificationsUseActiveProductSession(t *testing.T) {
	ipcServer := &IPCServer{manager: adminserver.NewSessionManager()}
	recorder := addActiveProductSession(t, ipcServer)
	ipcServer.NotifyKeysChanged(adminproto.KeysChangedNotification{KeyCount: 3})
	ipcServer.NotifyLocked(adminproto.SignerLockedNotification{Reason: "locked"})
	ipcServer.NotifyStatus("unlocked", 3)
	messages := recorder.messages(t)
	if len(messages) != 3 || messages[0]["type"] != protocol.MsgTypeKeysChanged ||
		messages[1]["type"] != protocol.MsgTypeSignerLocked || messages[2]["type"] != protocol.MsgTypeStatus {
		t.Fatalf("notification sequence mismatch: %#v", messages)
	}
}

func TestIPCOutboundMessagesExcludePendingAndPreAuthSessions(t *testing.T) {
	ipcServer := &IPCServer{manager: adminserver.NewSessionManager()}
	active := addActiveProductSession(t, ipcServer)

	pendingRecorder := &ipcJSONRecorderConn{}
	pending := adminserver.NewSession(
		adminproto.NewUnixAdminConn(pendingRecorder, nil),
		adminserver.SessionDeps{},
	)
	if !ipcServer.sessionManager().RegisterPending(pending) {
		t.Fatal("RegisterPending() = false, want true")
	}

	preAuthRecorder := &ipcJSONRecorderConn{}
	preAuth := adminserver.NewSession(
		adminproto.NewUnixAdminConn(preAuthRecorder, nil),
		adminserver.SessionDeps{},
	)
	if !ipcServer.sessionManager().RegisterPreAuthPending(preAuth) {
		t.Fatal("RegisterPreAuthPending() = false, want true")
	}

	if !ipcServer.SendSignRequest(&signerapproval.SignRequest{ID: "req-1", Address: "ADDR"}) {
		t.Fatal("SendSignRequest() = false, want true")
	}
	if !ipcServer.SendSignRequestCanceled(&signerapproval.SignRequestCanceled{
		ID: "req-1", Reason: signerapproval.SignRequestCancelReasonClientCanceled,
	}) {
		t.Fatal("SendSignRequestCanceled() = false, want true")
	}
	if !ipcServer.SendTokenProvisioningRequest(&signerapproval.TokenProvisioningRequest{
		ID: "token-1",
	}) {
		t.Fatal("SendTokenProvisioningRequest() = false, want true")
	}
	ipcServer.NotifyKeysChanged(adminproto.KeysChangedNotification{KeyCount: 3})
	ipcServer.NotifyLocked(adminproto.SignerLockedNotification{Reason: "locked"})
	ipcServer.NotifyStatus("unlocked", 3)

	if messages := active.messages(t); len(messages) != 6 {
		t.Fatalf("active message count = %d, want 6: %#v", len(messages), messages)
	}
	if messages := pendingRecorder.messages(t); len(messages) != 0 {
		t.Fatalf("pending session received outbound messages: %#v", messages)
	}
	if messages := preAuthRecorder.messages(t); len(messages) != 0 {
		t.Fatalf("pre-auth session received outbound messages: %#v", messages)
	}
}
