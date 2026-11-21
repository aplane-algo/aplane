// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"

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
	oldSession := adminserver.NewSession(adminproto.NewUnixAdminConn(oldServer), adminserver.SessionDeps{}, adminserver.OriginLocal)
	_ = registerPendingSession(server.manager, oldSession)
	server.manager.PromoteToActive(oldSession)

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

	newSession := adminserver.NewSession(adminproto.NewUnixAdminConn(&hubStubConn{}), adminserver.SessionDeps{}, adminserver.OriginLocal)
	if !registerPendingSession(server.manager, newSession) {
		t.Fatal("registerPendingSession(newSession) = false, want true")
	}
	replaced := server.manager.PromoteToActive(newSession)
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

	ir := signer.productRuntime()
	ir.Config().SetLockOnDisconnect(true)

	ipcServer := &IPCServer{
		signer:  signer,
		manager: adminserver.NewSessionManager(),
	}
	oldSession := adminserver.NewSession(adminproto.NewUnixAdminConn(&hubStubConn{}), signer.adminSessionDeps(), adminserver.OriginLocal)
	if !registerPendingSession(ipcServer.manager, oldSession) {
		t.Fatal("registerPendingSession(oldSession) = false, want true")
	}
	ipcServer.manager.PromoteToActive(oldSession)

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
		ProtocolVersion: protocol.AdminProtocolVersion,
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

	ir := signer.productRuntime()
	ipcServer := &IPCServer{
		signer:  signer,
		manager: adminserver.NewSessionManager(),
	}
	signer.ipcServer = ipcServer
	signer.hub = signer.ipcServer

	oldServer, oldClient := net.Pipe()
	defer func() { _ = oldClient.Close() }()
	oldSession := adminserver.NewSession(adminproto.NewUnixAdminConn(oldServer), signer.adminSessionDeps(), adminserver.OriginLocal)
	oldSession.Bind(auth.NewProductIdentity("test"), ir)
	if !registerPendingSession(ipcServer.manager, oldSession) {
		t.Fatal("registerPendingSession(oldSession) = false, want true")
	}
	ipcServer.manager.PromoteToActive(oldSession)

	approvalResult := make(chan error, 1)
	go func() {
		// Displacement withdraws the prompt shown to the old session: it
		// ends as ErrApproverDisplaced, not as a rejection.
		response, err := ir.RequestSigningApprovalPrompt(context.Background(), signerapproval.Prompt{RequestID: "displaced-prompt", Address: "A", TxnSender: "A", Description: "desc"}, time.Minute)
		if !errors.Is(err, signerapproval.ErrApproverDisplaced) || response.Approved {
			approvalResult <- fmt.Errorf("response = %+v, err = %v; want the prompt withdrawn with ErrApproverDisplaced", response, err)
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
			adminproto.NewUnixAdminConn(newServer),
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
		ProtocolVersion: protocol.AdminProtocolVersion,
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
	// Keep reading the replacement: the withdrawal's cancel notice is written
	// to it, and an unread net.Pipe would hold that write.
	if err := newClient.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = io.Copy(io.Discard, newReader) }()

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
