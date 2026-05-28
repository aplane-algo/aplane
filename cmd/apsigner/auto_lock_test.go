// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
)

func TestSessionTimeoutLocksSignerClearsKeysAndNotifiesIPC(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.DefaultIdentityID)
	ir.SetSessionTimeout(20 * time.Millisecond)
	session := ir.SnapshotKeySession()
	session.InitializeSession()
	ir.PublishSnapshot(
		map[string]string{"ADDR": "identities/default/keys/ADDR.key"},
		map[string]string{"ADDR": "ed25519"},
		map[string]int{"ADDR": 0},
	)

	msgCh := make(chan protocol.SignerLockedMessage, 1)
	server.ipcServer = newIPCServerWithActiveConn(&capturingConn{lockedMsgCh: msgCh})

	// Re-wire the identity with an onLocked callback that notifies IPC
	irWithCallback := identity.New(identity.Config{
		Authenticator:  auth.NewTokenAuthenticator("test-token"),
		ID:             auth.DefaultIdentityID,
		KeyStore:       ir.KeyStore(),
		KeyPaths:       ir.KeyPaths(),
		SessionTimeout: 20 * time.Millisecond,
		OnLocked: func() {
			server.ipcServer.NotifyLocked(auth.DefaultIdentityID, adminproto.SignerLockedNotification{Reason: "locked"})
		},
	})
	// Replace in registry by creating a new one
	server.registry = identity.NewRegistry()
	_ = server.registry.Register(irWithCallback)
	server.wireReloadFunc(irWithCallback)
	irWithCallback.SetUnlocked()
	irWithCallback.PublishSnapshot(
		map[string]string{"ADDR": "identities/default/keys/ADDR.key"},
		map[string]string{"ADDR": "ed25519"},
		map[string]int{"ADDR": 0},
	)

	irWithCallback.ResetSessionTimer()
	defer irWithCallback.StopSessionTimer()

	// Wait for the IPC lock notification, which fires after performLock
	// has cleared the key maps. This avoids a race between the state
	// transition (observed by isUnlocked) and the map clearing.
	select {
	case msg := <-msgCh:
		if msg.Type != protocol.MsgTypeSignerLocked {
			t.Fatalf("locked msg type = %q, want %q", msg.Type, protocol.MsgTypeSignerLocked)
		}
		if msg.Reason != "locked" {
			t.Fatalf("locked msg reason = %q, want %q", msg.Reason, "locked")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for signer_locked notification")
	}

	if server.isUnlocked() {
		t.Fatal("signer remained unlocked after session timeout")
	}

	keys, keyTypes, lsigSizes := irWithCallback.KeySnapshot()
	keyCount := len(keys)
	typeCount := len(keyTypes)
	lsigCount := len(lsigSizes)
	if keyCount != 0 || typeCount != 0 || lsigCount != 0 {
		t.Fatalf("expected cleared key maps, got keys=%d keyTypes=%d lsigSizes=%d", keyCount, typeCount, lsigCount)
	}
}

type capturingConn struct {
	mu          sync.Mutex
	lockedMsgCh chan protocol.SignerLockedMessage
}

func (c *capturingConn) Read([]byte) (int, error) { return 0, nil }

func (c *capturingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var msg protocol.SignerLockedMessage
	if err := json.Unmarshal(b, &msg); err == nil && msg.Type == protocol.MsgTypeSignerLocked {
		select {
		case c.lockedMsgCh <- msg:
		default:
		}
	}
	return len(b), nil
}

func (c *capturingConn) Close() error                     { return nil }
func (c *capturingConn) LocalAddr() net.Addr              { return nil }
func (c *capturingConn) RemoteAddr() net.Addr             { return nil }
func (c *capturingConn) SetDeadline(time.Time) error      { return nil }
func (c *capturingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *capturingConn) SetWriteDeadline(time.Time) error { return nil }
