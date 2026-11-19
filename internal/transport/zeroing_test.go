// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package transport

import (
	"bytes"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

func isZeroed(b []byte) bool {
	return len(b) > 0 && bytes.Equal(b, make([]byte, len(b)))
}

// The auth request's passphrase copy is zeroed once the handshake ends. The
// stub keeps the sent message, whose passphrase shares the sender's bytes.
func TestAuthenticateZeroesSentPassphrase(t *testing.T) {
	conn := &stubAdminProtocolConn{reads: [][]byte{
		mustMarshalProtocolMessage(t, protocol.BaseMessage{Type: protocol.MsgTypeAuthRequired}),
		mustMarshalProtocolMessage(t, protocol.AuthResultMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAuthResult},
			Success:     true,
		}),
	}}
	if err := authenticate(conn, "auth-secret", time.Second); err != nil {
		t.Fatalf("authenticate() error = %v", err)
	}
	sent, ok := conn.firstWrite()
	if !ok {
		t.Fatal("auth request was not written")
	}
	if passphrase := sent.(protocol.AuthMessage).Passphrase; !isZeroed(passphrase) {
		t.Fatalf("auth passphrase left as %q after the handshake", []byte(passphrase))
	}
}

// The unlock request's passphrase copy is zeroed once the request ends.
func TestUnlockWithDispatcherZeroesSentPassphrase(t *testing.T) {
	conn := &stubAdminProtocolConn{readFunc: func(s *stubAdminProtocolConn) ([]byte, error) {
		sent, ok := s.firstWrite()
		if !ok || s.readIndex > 0 {
			return nil, errors.New("no more messages")
		}
		s.readIndex++
		return mustMarshalProtocolMessage(t, protocol.UnlockResultMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeUnlockResult, ID: sent.(protocol.UnlockMessage).ID},
			Success:     true,
		}), nil
	}}
	if _, err := unlockWithDispatcher(newDispatcher(conn), "unlock-secret", 5*time.Second); err != nil {
		t.Fatalf("unlockWithDispatcher() error = %v", err)
	}
	sent, _ := conn.firstWrite()
	if passphrase := sent.(protocol.UnlockMessage).Passphrase; !isZeroed(passphrase) {
		t.Fatalf("unlock passphrase left as %q after the request", []byte(passphrase))
	}
}

// countedField counts how often its message is encoded.
type countedField struct{ calls *atomic.Int32 }

func (f countedField) MarshalJSON() ([]byte, error) {
	f.calls.Add(1)
	return []byte(`"value"`), nil
}

type countedRequest struct {
	protocol.BaseMessage
	Field countedField `json:"field"`
}

// encodingConn encodes each written message as the real clients do.
type encodingConn struct{ stubAdminProtocolConn }

func (c *encodingConn) WriteJSON(v interface{}) error {
	data, err := protocol.MarshalAdminMessage(v)
	if err != nil {
		return err
	}
	protocol.SensitiveBytes(data).Zero()
	return c.stubAdminProtocolConn.WriteJSON(v)
}

// A request is encoded once, for the wire. Reading its ID used to encode it a
// second time and leave that unzeroed copy of anything secret it carried.
func TestDispatcherRequestEncodesMessageOnce(t *testing.T) {
	calls := &atomic.Int32{}
	conn := &encodingConn{}
	conn.readFunc = func(s *stubAdminProtocolConn) ([]byte, error) {
		if s.writeCount() == 0 || s.readIndex > 0 {
			return nil, errors.New("no more messages")
		}
		s.readIndex++
		return mustMarshalProtocolMessage(t, protocol.UnlockResultMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeUnlockResult, ID: "counted-1"},
			Success:     true,
		}), nil
	}
	request := countedRequest{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeUnlock, ID: "counted-1"},
		Field:       countedField{calls: calls},
	}
	if _, err := newDispatcher(conn).request(request, 5*time.Second); err != nil {
		t.Fatalf("request() error = %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("request encoded the message %d times, want 1", got)
	}
}
