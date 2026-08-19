// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
)

func TestTokenProvisioningRequiresProductAdmin(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ipcServer := &IPCServer{manager: adminserver.NewSessionManager()}
	server.ipcServer = ipcServer

	approved, err := server.requestTokenProvisioning("token-no-admin", "fp", "remote", time.Second)
	if err == nil {
		t.Fatal("requestTokenProvisioning(alice) error = nil, want no-client error")
	}
	if err.Error() != "no apadmin client connected" {
		t.Fatalf("requestTokenProvisioning(alice) error = %v, want no-client error", err)
	}
	if approved {
		t.Fatal("approved = true, want false")
	}
}

func TestTokenProvisioningRoutesToProductAdmin(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	productRuntime := server.productIdentityRuntime()
	ipcServer := &IPCServer{manager: adminserver.NewSessionManager()}
	server.ipcServer = ipcServer

	adminConn := addActiveProductSession(t, ipcServer)

	resultCh := make(chan struct {
		approved bool
		err      error
	}, 1)
	go func() {
		approved, err := server.requestTokenProvisioning("token-default", "fp", "remote", time.Second)
		resultCh <- struct {
			approved bool
			err      error
		}{approved: approved, err: err}
	}()

	var messages []map[string]any
	deadline := time.After(2 * time.Second)
	for len(messages) == 0 {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for alice token provisioning request")
		case <-time.After(10 * time.Millisecond):
			messages = adminConn.messages(t)
		}
	}
	if !reflectJSONSubset(messages[0], map[string]any{
		"kind":        string(protocol.MessageKindNotification),
		"type":        protocol.MsgTypeTokenProvisioningRequest,
		"id":          "token-default",
		"identity_id": "default",
	}) {
		t.Fatalf("product token provisioning request shape mismatch: %#v", messages[0])
	}

	productRuntime.HandleTokenProvisioningApprovalResponse(&signerapproval.TokenProvisioningResponse{
		ID:       "token-default",
		Approved: true,
	})

	select {
	case result := <-resultCh:
		if result.err != nil {
			t.Fatalf("requestTokenProvisioning(default) error = %v", result.err)
		}
		if !result.approved {
			t.Fatal("approved = false, want true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for token provisioning approval result")
	}
}
