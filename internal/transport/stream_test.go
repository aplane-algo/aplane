// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package transport

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestStreamClientSurfacesUnmatchedResponsesAsNotifications(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	client := NewStreamClient(clientConn)

	go func() {
		_, _ = serverConn.Write(mustJSONLine(t, protocol.AuthResultMessage{
			BaseMessage: protocol.BaseMessage{
				Type: protocol.MsgTypeAuthResult,
				ID:   "auth-1",
			},
			Success: true,
		}))
	}()

	select {
	case notification := <-client.Notifications():
		if notification.Base.Type != protocol.MsgTypeAuthResult {
			t.Fatalf("notification.Base.Type = %q, want %q", notification.Base.Type, protocol.MsgTypeAuthResult)
		}
		if notification.Base.Kind != protocol.MessageKindResponse {
			t.Fatalf("notification.Base.Kind = %q, want %q", notification.Base.Kind, protocol.MessageKindResponse)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for response notification")
	}
}

func TestStreamClientWriteJSONWritesLineDelimitedMessage(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	client := NewStreamClient(clientConn)
	done := make(chan []byte, 1)
	go func() {
		reader := bufio.NewReader(serverConn)
		line, _ := reader.ReadBytes('\n')
		done <- line
	}()

	err := client.WriteJSON(protocol.UnlockMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeUnlock,
			ID:   "unlock-1",
		},
		Passphrase: protocol.NewSensitiveBytes("secret"),
	})
	if err != nil {
		t.Fatalf("WriteJSON() error = %v", err)
	}

	select {
	case line := <-done:
		var msg protocol.UnlockMessage
		if err := json.Unmarshal(line[:len(line)-1], &msg); err != nil {
			t.Fatalf("json.Unmarshal() error = %v", err)
		}
		if msg.Type != protocol.MsgTypeUnlock || string(msg.Passphrase) != "secret" {
			t.Fatalf("decoded message = %+v, want unlock/secret", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for written message")
	}
}

func TestStreamClientCloseEmitsLifecycleOnReaderExit(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	client := NewStreamClient(clientConn)
	lifecycle := client.LifecycleEvents()

	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	_ = serverConn.Close()

	select {
	case event := <-lifecycle:
		if event.Type != LifecycleConnectionLost {
			t.Fatalf("first lifecycle event = %q, want %q", event.Type, LifecycleConnectionLost)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for connection-lost lifecycle event")
	}

	select {
	case event := <-lifecycle:
		if event.Type != LifecycleReaderStopped {
			t.Fatalf("second lifecycle event = %q, want %q", event.Type, LifecycleReaderStopped)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for reader-stopped lifecycle event")
	}
}

func TestStreamClientReadMessageReadsJSONLine(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	client := NewStreamClient(clientConn)
	go func() {
		_, _ = serverConn.Write(mustJSONLine(t, protocol.StatusMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeStatus},
			State:       "unlocked",
			KeyCount:    2,
		}))
	}()

	raw, err := client.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}
	var msg protocol.StatusMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if msg.State != "unlocked" || msg.KeyCount != 2 {
		t.Fatalf("decoded status = %+v, want unlocked/2", msg)
	}
}

func TestStreamClientCloseClearsQueuedNotifications(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()

	client := NewStreamClient(clientConn)
	notifications := client.Notifications()
	go func() {
		_, _ = serverConn.Write(mustJSONLine(t, protocol.ExportResultMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeExportResult, ID: "export-1"},
			Success:     true,
			Mnemonic:    protocol.NewSensitiveBytes("secret recovery phrase"),
		}))
	}()

	// Hold a reference to the queued frame, then put it back unconsumed: the
	// consumer stopped reading (as the TUI does on disconnect).
	var queued Notification
	select {
	case queued = <-notifications:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the export notification")
	}
	client.dispatcher.notifications <- queued

	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if len(client.dispatcher.notifications) != 0 {
		t.Fatal("queued notification survived Close")
	}
	if !bytes.Equal(queued.Raw, make([]byte, len(queued.Raw))) {
		t.Fatal("queued raw frame retained recovery material after Close")
	}
}
