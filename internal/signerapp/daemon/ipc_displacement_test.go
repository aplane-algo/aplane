// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

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

func TestOfferDisplacementKeepsExistingClientUntilReplacementPromoted(t *testing.T) {
	oldServer, oldClient := net.Pipe()
	defer func() { _ = oldClient.Close() }()
	server := &IPCServer{
		manager: adminserver.NewSessionManager(),
	}
	oldSession := adminserver.NewSession(adminproto.NewUnixAdminConn(oldServer, nil), adminserver.SessionDeps{})
	_ = server.manager.RegisterPending(auth.CurrentProductIdentityID(), oldSession)
	_, _ = server.manager.PromoteToActive(auth.CurrentProductIdentityID(), oldSession)

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
	if server.activeSession() != oldSession {
		t.Fatal("active session changed before replacement promotion")
	}

	newSession := adminserver.NewSession(adminproto.NewUnixAdminConn(&hubStubConn{}, nil), adminserver.SessionDeps{})
	if !server.manager.RegisterPending(auth.CurrentProductIdentityID(), newSession) {
		t.Fatal("RegisterPending(newSession) = false, want true")
	}
	replaced, ok := server.manager.PromoteToActive(auth.CurrentProductIdentityID(), newSession)
	if !ok {
		t.Fatal("PromoteToActive(newSession) = false, want true")
	}
	if replaced != oldSession {
		t.Fatal("PromoteToActive did not return old active session")
	}
	adminserver.DisplaceSession(replaced)

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

	if server.activeSession() != newSession {
		t.Fatal("replacement session should be active after displacement")
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

func TestDisplacementReplacementAuthFailureKeepsOldOwner(t *testing.T) {
	signer, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := signer.registry.Get(auth.DefaultIdentityID)
	ir.Config().SetLockOnDisconnect(true)

	ipcServer := &IPCServer{
		signer:  signer,
		manager: adminserver.NewSessionManager(),
	}
	oldSession := adminserver.NewSession(adminproto.NewUnixAdminConn(&hubStubConn{}, nil), signer.adminSessionDeps())
	if !ipcServer.manager.RegisterPending(auth.DefaultIdentityID, oldSession) {
		t.Fatal("RegisterPending(oldSession) = false, want true")
	}
	if _, ok := ipcServer.manager.PromoteToActive(auth.DefaultIdentityID, oldSession); !ok {
		t.Fatal("PromoteToActive(oldSession) = false, want true")
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
	readAdminMessageType(t, clientConn, reader, protocol.MsgTypeClientExists)
	writeAdminMessage(t, clientConn, protocol.DisplaceConfirmMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeDisplaceConfirm,
		},
	})
	readAdminMessageType(t, clientConn, reader, protocol.MsgTypeAuthRequired)
	writeAdminMessage(t, clientConn, protocol.AuthMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeAuth,
		},
		Passphrase: protocol.NewSensitiveBytes("wrong-passphrase"),
	})

	rawAuth := readAdminMessageType(t, clientConn, reader, protocol.MsgTypeAuthResult)
	var authResult protocol.AuthResultMessage
	if err := json.Unmarshal(rawAuth, &authResult); err != nil {
		t.Fatalf("decode auth_result: %v", err)
	}
	if authResult.Success {
		t.Fatal("auth_result success = true, want false")
	}

	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for failed replacement session cleanup")
	}

	if ipcServer.activeIdentitySession(auth.DefaultIdentityID) != oldSession {
		t.Fatal("old active session was not retained after replacement auth failure")
	}
	if !ir.IsUnlocked() {
		t.Fatal("identity locked even though old active owner remained connected")
	}
}
