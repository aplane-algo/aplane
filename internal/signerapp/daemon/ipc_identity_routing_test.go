// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	"sync"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/protocol"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
)

func addActiveIdentitySession(t *testing.T, server *IPCServer, identityID string) *ipcJSONRecorderConn {
	t.Helper()
	recorder := &ipcJSONRecorderConn{}
	session := adminserver.NewSession(adminproto.NewUnixAdminConn(recorder, nil), adminserver.SessionDeps{})
	if !server.sessionManager().RegisterPending(identityID, session) {
		t.Fatalf("RegisterPending(%q) = false, want true", identityID)
	}
	if _, ok := server.sessionManager().PromoteToActive(identityID, session); !ok {
		t.Fatalf("PromoteToActive(%q) = false, want true", identityID)
	}
	return recorder
}

func TestIPCSendSignRequestRoutesOnlyToTargetIdentity(t *testing.T) {
	ipcServer := &IPCServer{manager: adminserver.NewSessionManager()}
	alice := addActiveIdentitySession(t, ipcServer, "alice")
	bob := addActiveIdentitySession(t, ipcServer, "bob")

	if !ipcServer.SendSignRequest("alice", &signerapproval.SignRequest{ID: "req-alice", Address: "ADDR"}) {
		t.Fatal("SendSignRequest(alice) = false, want true")
	}

	aliceMsgs := alice.messages(t)
	if len(aliceMsgs) != 1 {
		t.Fatalf("alice message count = %d, want 1", len(aliceMsgs))
	}
	if !reflectJSONSubset(aliceMsgs[0], map[string]any{
		"kind": string(protocol.MessageKindNotification),
		"type": protocol.MsgTypeSignRequest,
		"id":   "req-alice",
	}) {
		t.Fatalf("alice sign_request shape mismatch: %#v", aliceMsgs[0])
	}
	if bobMsgs := bob.messages(t); len(bobMsgs) != 0 {
		t.Fatalf("bob message count = %d, want 0: %#v", len(bobMsgs), bobMsgs)
	}
}

func TestIPCTokenProvisioningRoutesOnlyToTargetIdentity(t *testing.T) {
	ipcServer := &IPCServer{manager: adminserver.NewSessionManager()}
	alice := addActiveIdentitySession(t, ipcServer, "alice")
	bob := addActiveIdentitySession(t, ipcServer, "bob")

	if !ipcServer.SendTokenProvisioningRequest("bob", &signerapproval.TokenProvisioningRequest{ID: "req-bob", IdentityID: "bob"}) {
		t.Fatal("SendTokenProvisioningRequest(bob) = false, want true")
	}

	if aliceMsgs := alice.messages(t); len(aliceMsgs) != 0 {
		t.Fatalf("alice message count = %d, want 0: %#v", len(aliceMsgs), aliceMsgs)
	}
	bobMsgs := bob.messages(t)
	if len(bobMsgs) != 1 {
		t.Fatalf("bob message count = %d, want 1", len(bobMsgs))
	}
	if !reflectJSONSubset(bobMsgs[0], map[string]any{
		"kind":        string(protocol.MessageKindNotification),
		"type":        protocol.MsgTypeTokenProvisioningRequest,
		"id":          "req-bob",
		"identity_id": "bob",
	}) {
		t.Fatalf("bob token_provisioning_request shape mismatch: %#v", bobMsgs[0])
	}
}

func TestIPCSendSignRequestCanceledRoutesOnlyToTargetIdentity(t *testing.T) {
	ipcServer := &IPCServer{manager: adminserver.NewSessionManager()}
	alice := addActiveIdentitySession(t, ipcServer, "alice")
	bob := addActiveIdentitySession(t, ipcServer, "bob")

	if !ipcServer.SendSignRequestCanceled("alice", &signerapproval.SignRequestCanceled{
		ID:     "req-alice",
		Reason: signerapproval.SignRequestCancelReasonClientCanceled,
	}) {
		t.Fatal("SendSignRequestCanceled(alice) = false, want true")
	}

	aliceMsgs := alice.messages(t)
	if len(aliceMsgs) != 1 {
		t.Fatalf("alice message count = %d, want 1", len(aliceMsgs))
	}
	if !reflectJSONSubset(aliceMsgs[0], map[string]any{
		"kind":   string(protocol.MessageKindNotification),
		"type":   protocol.MsgTypeSignRequestCanceled,
		"id":     "req-alice",
		"reason": signerapproval.SignRequestCancelReasonClientCanceled,
	}) {
		t.Fatalf("alice sign_request_canceled shape mismatch: %#v", aliceMsgs[0])
	}
	if bobMsgs := bob.messages(t); len(bobMsgs) != 0 {
		t.Fatalf("bob message count = %d, want 0: %#v", len(bobMsgs), bobMsgs)
	}
}

func TestIPCNotificationsRouteOnlyToTargetIdentity(t *testing.T) {
	ipcServer := &IPCServer{manager: adminserver.NewSessionManager()}
	alice := addActiveIdentitySession(t, ipcServer, "alice")
	bob := addActiveIdentitySession(t, ipcServer, "bob")

	ipcServer.NotifyKeysChanged("alice", adminproto.KeysChangedNotification{KeyCount: 3})
	ipcServer.NotifyLocked("bob", adminproto.SignerLockedNotification{Reason: "locked"})

	aliceMsgs := alice.messages(t)
	if len(aliceMsgs) != 1 {
		t.Fatalf("alice message count = %d, want 1", len(aliceMsgs))
	}
	if !reflectJSONSubset(aliceMsgs[0], map[string]any{
		"kind":      string(protocol.MessageKindNotification),
		"type":      protocol.MsgTypeKeysChanged,
		"key_count": float64(3),
	}) {
		t.Fatalf("alice keys_changed shape mismatch: %#v", aliceMsgs[0])
	}

	bobMsgs := bob.messages(t)
	if len(bobMsgs) != 1 {
		t.Fatalf("bob message count = %d, want 1", len(bobMsgs))
	}
	if !reflectJSONSubset(bobMsgs[0], map[string]any{
		"kind":   string(protocol.MessageKindNotification),
		"type":   protocol.MsgTypeSignerLocked,
		"reason": "locked",
	}) {
		t.Fatalf("bob signer_locked shape mismatch: %#v", bobMsgs[0])
	}
}

func TestConcurrentIPCSendSignRequestsForDifferentIdentities(t *testing.T) {
	ipcServer := &IPCServer{manager: adminserver.NewSessionManager()}
	alice := addActiveIdentitySession(t, ipcServer, "alice")
	bob := addActiveIdentitySession(t, ipcServer, "bob")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if !ipcServer.SendSignRequest("alice", &signerapproval.SignRequest{ID: "req-alice", Address: "ADDR-A"}) {
			t.Error("SendSignRequest(alice) = false, want true")
		}
	}()
	go func() {
		defer wg.Done()
		if !ipcServer.SendSignRequest("bob", &signerapproval.SignRequest{ID: "req-bob", Address: "ADDR-B"}) {
			t.Error("SendSignRequest(bob) = false, want true")
		}
	}()
	wg.Wait()

	if msgs := alice.messages(t); len(msgs) != 1 || msgs[0]["id"] != "req-alice" {
		t.Fatalf("alice messages = %#v, want req-alice only", msgs)
	}
	if msgs := bob.messages(t); len(msgs) != 1 || msgs[0]["id"] != "req-bob" {
		t.Fatalf("bob messages = %#v, want req-bob only", msgs)
	}
}
