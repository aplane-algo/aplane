// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/protocol"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
)

func TestTokenProvisioningRequiresAdminForTargetIdentity(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	alice := registerAdditionalAdminTestIdentity(t, server, "alice")
	_ = registerAdditionalAdminTestIdentity(t, server, "bob")
	ipcServer := &IPCServer{manager: adminproto.NewSessionManager()}
	server.ipcServer = ipcServer
	server.wireApprovalCoordinator(alice)

	bob := addActiveIdentitySession(t, ipcServer, "bob")

	approved, err := server.requestTokenProvisioning("token-alice-no-admin", "alice", "fp", "remote", time.Second)
	if err == nil {
		t.Fatal("requestTokenProvisioning(alice) error = nil, want no-client error")
	}
	if !strings.Contains(err.Error(), "no apadmin client connected") {
		t.Fatalf("requestTokenProvisioning(alice) error = %v, want no-client error", err)
	}
	if approved {
		t.Fatal("approved = true, want false")
	}
	if bobMsgs := bob.messages(t); len(bobMsgs) != 0 {
		t.Fatalf("bob message count = %d, want 0: %#v", len(bobMsgs), bobMsgs)
	}
}

func TestTokenProvisioningRoutesToTargetIdentityAdmin(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	alice := registerAdditionalAdminTestIdentity(t, server, "alice")
	_ = registerAdditionalAdminTestIdentity(t, server, "bob")
	ipcServer := &IPCServer{manager: adminproto.NewSessionManager()}
	server.ipcServer = ipcServer
	server.wireApprovalCoordinator(alice)

	aliceConn := addActiveIdentitySession(t, ipcServer, "alice")
	bobConn := addActiveIdentitySession(t, ipcServer, "bob")

	resultCh := make(chan struct {
		approved bool
		err      error
	}, 1)
	go func() {
		approved, err := server.requestTokenProvisioning("token-alice", "alice", "fp", "remote", time.Second)
		resultCh <- struct {
			approved bool
			err      error
		}{approved: approved, err: err}
	}()

	var aliceMsgs []map[string]any
	deadline := time.After(2 * time.Second)
	for len(aliceMsgs) == 0 {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for alice token provisioning request")
		case <-time.After(10 * time.Millisecond):
			aliceMsgs = aliceConn.messages(t)
		}
	}
	if !reflectJSONSubset(aliceMsgs[0], map[string]any{
		"kind":        string(protocol.MessageKindNotification),
		"type":        protocol.MsgTypeTokenProvisioningRequest,
		"id":          "token-alice",
		"identity_id": "alice",
	}) {
		t.Fatalf("alice token provisioning request shape mismatch: %#v", aliceMsgs[0])
	}
	if bobMsgs := bobConn.messages(t); len(bobMsgs) != 0 {
		t.Fatalf("bob message count = %d, want 0: %#v", len(bobMsgs), bobMsgs)
	}

	alice.HandleTokenProvisioningApprovalResponse(&signerapproval.TokenProvisioningResponse{
		ID:       "token-alice",
		Approved: true,
	})

	select {
	case result := <-resultCh:
		if result.err != nil {
			t.Fatalf("requestTokenProvisioning(alice) error = %v", result.err)
		}
		if !result.approved {
			t.Fatal("approved = false, want true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for token provisioning approval result")
	}
}
