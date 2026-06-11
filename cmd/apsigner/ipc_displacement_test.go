// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bufio"
	"encoding/json"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	"net"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestOfferDisplacementDisplacesExistingClientOnConfirm(t *testing.T) {
	oldServer, oldClient := net.Pipe()
	defer func() { _ = oldClient.Close() }()
	server := newIPCServerWithActiveConn(oldServer)

	newServer, newClient := net.Pipe()
	defer func() { _ = newClient.Close() }()

	oldMsgCh := make(chan protocol.DisplacedMessage, 1)
	oldErrCh := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(oldClient)
		line, err := reader.ReadBytes('\n')
		if err != nil {
			oldErrCh <- err
			return
		}
		var msg protocol.DisplacedMessage
		oldErrCh <- json.Unmarshal(line[:len(line)-1], &msg)
		oldMsgCh <- msg
	}()

	go func() {
		reader := bufio.NewReader(newClient)
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		var msg protocol.ClientExistsMessage
		if err := json.Unmarshal(line[:len(line)-1], &msg); err != nil {
			return
		}
		data, _ := protocol.MarshalAdminMessage(protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeDisplaceConfirm,
		})
		_, _ = newClient.Write(append(data, '\n'))
	}()

	ok := server.offerDisplacement(newServer)
	if !ok {
		t.Fatal("offerDisplacement() = false, want true")
	}

	select {
	case err := <-oldErrCh:
		if err != nil {
			t.Fatalf("old client read error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for displaced message")
	}

	select {
	case msg := <-oldMsgCh:
		if msg.Type != protocol.MsgTypeDisplaced {
			t.Fatalf("displaced msg type = %q, want %q", msg.Type, protocol.MsgTypeDisplaced)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for displaced message payload")
	}

	if server.activeSession() != nil {
		t.Fatal("active session should be cleared after displacement")
	}
}

func TestPreboundAdminSessionDoesNotDisplaceDifferentIdentity(t *testing.T) {
	signer, cleanup := setupTestSigner(t)
	defer cleanup()

	ipcServer := &IPCServer{
		signer:  signer,
		manager: adminserver.NewSessionManager(),
	}
	bobSession := adminserver.NewSession(adminproto.NewUnixAdminConn(&hubStubConn{}, nil), signer.adminSessionDeps())
	_ = ipcServer.manager.RegisterPending("bob", bobSession)
	_, _ = ipcServer.manager.PromoteToActive("bob", bobSession)

	newServer, newClient := net.Pipe()
	defer func() { _ = newClient.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		ipcServer.acceptAdminSession(adminproto.NewUnixAdminConn(newServer, nil), "ssh", "ssh-passphrase", "alice")
	}()

	reader := bufio.NewReader(newClient)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatalf("ReadBytes() error = %v", err)
	}
	var msg protocol.AuthRequiredMessage
	if err := json.Unmarshal(line[:len(line)-1], &msg); err != nil {
		t.Fatalf("Unmarshal(auth_required) error = %v", err)
	}
	if msg.Type != protocol.MsgTypeAuthRequired {
		t.Fatalf("first message type = %q, want %q", msg.Type, protocol.MsgTypeAuthRequired)
	}
	if ipcServer.activeIdentitySession("bob") != bobSession {
		t.Fatal("bob active session was displaced by alice session")
	}
	if ipcServer.activeIdentitySession(auth.CurrentProductIdentityID()) != nil {
		t.Fatal("product active session unexpectedly set")
	}

	_ = newClient.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for admin session to exit")
	}
}
