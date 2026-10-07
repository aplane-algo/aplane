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

func TestClientEnrollmentRequiresProductAdmin(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ipcServer := &IPCServer{manager: adminserver.NewSessionManager()}
	server.ipcServer = ipcServer

	approved, err := server.requestClientEnrollment("enroll-no-admin", "fp", "", "remote", time.Second)
	if err == nil {
		t.Fatal("requestClientEnrollment(alice) error = nil, want no-client error")
	}
	if err.Error() != "no apadmin client connected" {
		t.Fatalf("requestClientEnrollment(alice) error = %v, want no-client error", err)
	}
	if approved {
		t.Fatal("approved = true, want false")
	}
}

func TestClientEnrollmentRoutesToProductAdmin(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	productRuntime := server.productRuntime()
	ipcServer := &IPCServer{manager: adminserver.NewSessionManager()}
	server.ipcServer = ipcServer

	adminConn := addActiveProductSession(t, ipcServer)

	resultCh := make(chan struct {
		approved bool
		err      error
	}, 1)
	go func() {
		approved, err := server.requestClientEnrollment("enroll-default", "fp", "laptop", "remote", time.Second)
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
			t.Fatal("timed out waiting for alice client enrollment request")
		case <-time.After(10 * time.Millisecond):
			messages = adminConn.messages(t)
		}
	}
	if !reflectJSONSubset(messages[0], map[string]any{
		"kind":  string(protocol.MessageKindNotification),
		"type":  protocol.MsgTypeClientEnrollmentRequest,
		"id":    "enroll-default",
		"label": "laptop",
	}) {
		t.Fatalf("product client enrollment request shape mismatch: %#v", messages[0])
	}

	productRuntime.HandleClientEnrollmentApprovalResponse(&signerapproval.ClientEnrollmentResponse{
		ID:       "enroll-default",
		Approved: true,
	})

	select {
	case result := <-resultCh:
		if result.err != nil {
			t.Fatalf("requestClientEnrollment(default) error = %v", result.err)
		}
		if !result.approved {
			t.Fatal("approved = false, want true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for client enrollment approval result")
	}
}
