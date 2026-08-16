// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
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
	_ = server.manager.RegisterPending(oldSession)
	_, _ = server.manager.PromoteToActive(oldSession)

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
	if !server.manager.RegisterPending(newSession) {
		t.Fatal("RegisterPending(newSession) = false, want true")
	}
	replaced, ok := server.manager.PromoteToActive(newSession)
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
	if !ipcServer.manager.RegisterPending(oldSession) {
		t.Fatal("RegisterPending(oldSession) = false, want true")
	}
	if _, ok := ipcServer.manager.PromoteToActive(oldSession); !ok {
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
		Passphrase:      protocol.NewSensitiveBytes("wrong-passphrase"),
		ProtocolVersion: testAdminProtocolVersion(),
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

	if ipcServer.activeSession() != oldSession {
		t.Fatal("old active session was not retained after replacement auth failure")
	}
	if !ir.IsUnlocked() {
		t.Fatal("identity locked even though old active owner remained connected")
	}
}

func TestDisplacementFailsDeliveredApprovalPrompt(t *testing.T) {
	signer, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := signer.registry.Get(auth.DefaultIdentityID)
	ipcServer := &IPCServer{
		signer:  signer,
		manager: adminserver.NewSessionManager(),
	}
	signer.ipcServer = ipcServer

	oldServer, oldClient := net.Pipe()
	defer func() { _ = oldClient.Close() }()
	oldSession := adminserver.NewSession(adminproto.NewUnixAdminConn(oldServer, nil), signer.adminSessionDeps())
	oldSession.Bind(auth.NewDefaultIdentity("test"), ir)
	if !ipcServer.manager.RegisterPending(oldSession) {
		t.Fatal("RegisterPending(oldSession) = false, want true")
	}
	if _, ok := ipcServer.manager.PromoteToActive(oldSession); !ok {
		t.Fatal("PromoteToActive(oldSession) = false, want true")
	}

	approvalResult := make(chan error, 1)
	go func() {
		response, err := ir.RequestSigningApprovalResponse("displaced-prompt", "A", "A", "desc", 0, 0, nil, time.Minute)
		if err != nil {
			approvalResult <- err
			return
		}
		if response.Approved || response.Reason != "apadmin displaced" {
			approvalResult <- fmt.Errorf("response = %+v, want rejected apadmin displaced response", response)
			return
		}
		approvalResult <- nil
	}()

	oldReader := bufio.NewReader(oldClient)
	readAdminMessageType(t, oldClient, oldReader, protocol.MsgTypeSignRequest)

	newServer, newClient := net.Pipe()
	defer func() { _ = newClient.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		ipcServer.acceptAdminSession(
			adminproto.NewUnixAdminConn(newServer, nil),
			adminserver.TransportIPC,
			"ipc-passphrase",
		)
	}()

	newReader := bufio.NewReader(newClient)
	readAdminMessageType(t, newClient, newReader, protocol.MsgTypeClientExists)
	writeAdminMessage(t, newClient, protocol.DisplaceConfirmMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeDisplaceConfirm,
		},
	})
	readAdminMessageType(t, newClient, newReader, protocol.MsgTypeAuthRequired)
	writeAdminMessage(t, newClient, protocol.AuthMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeAuth,
		},
		Passphrase:      protocol.NewSensitiveBytes(string(testPassphrase)),
		ProtocolVersion: testAdminProtocolVersion(),
	})

	rawAuth := readAdminMessageType(t, newClient, newReader, protocol.MsgTypeAuthResult)
	var authResult protocol.AuthResultMessage
	if err := json.Unmarshal(rawAuth, &authResult); err != nil {
		t.Fatalf("decode auth_result: %v", err)
	}
	if !authResult.Success {
		t.Fatalf("auth_result success = false: %+v", authResult)
	}
	readAdminMessageType(t, oldClient, oldReader, protocol.MsgTypeDisplaced)
	readAdminMessageType(t, newClient, newReader, protocol.MsgTypeStatus)

	select {
	case err := <-approvalResult:
		if err != nil {
			t.Fatalf("approval result error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending approval did not finish after displacement")
	}

	_ = newClient.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for replacement session cleanup")
	}
}
