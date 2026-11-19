// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package transport

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

func isZeroed(b []byte) bool {
	return len(b) > 0 && bytes.Equal(b, make([]byte, len(b)))
}

// frameRecordingConn encodes each written message as the real clients do and
// keeps a copy of the frame, so a test can read what went on the wire.
type frameRecordingConn struct {
	stubAdminProtocolConn
	frames [][]byte
}

func (c *frameRecordingConn) WriteJSON(v interface{}) error {
	data, err := protocol.MarshalAdminMessage(v)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.frames = append(c.frames, bytes.Clone(data))
	c.mu.Unlock()
	protocol.SensitiveBytes(data).Zero()
	return c.stubAdminProtocolConn.WriteJSON(v)
}

// The auth, auth_only and unlock frames carry the caller's passphrase, taken
// as bytes. The message's copy is zeroed once the request ends, and the
// caller's buffer is left for the caller to zero.
func TestPassphraseRequestsCarryTheCallersBytesAndZeroTheirCopy(t *testing.T) {
	authReplies := func(t *testing.T) [][]byte {
		return [][]byte{
			mustMarshalProtocolMessage(t, protocol.BaseMessage{Type: protocol.MsgTypeAuthRequired}),
			mustMarshalProtocolMessage(t, protocol.AuthResultMessage{
				BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAuthResult},
				Success:     true,
			}),
		}
	}
	tests := []struct {
		name string
		run  func(*testing.T, *frameRecordingConn, []byte) error
		sent func(interface{}) protocol.SensitiveBytes
	}{
		{
			name: "auth",
			run: func(t *testing.T, conn *frameRecordingConn, passphrase []byte) error {
				conn.reads = authReplies(t)
				return authenticate(conn, passphrase, time.Second)
			},
			sent: func(v interface{}) protocol.SensitiveBytes { return v.(protocol.AuthMessage).Passphrase },
		},
		{
			name: "auth_only",
			run: func(t *testing.T, conn *frameRecordingConn, passphrase []byte) error {
				conn.reads = authReplies(t)
				return authenticateOnly(conn, passphrase, time.Second)
			},
			sent: func(v interface{}) protocol.SensitiveBytes { return v.(protocol.AuthMessage).Passphrase },
		},
		{
			name: "unlock",
			run: func(t *testing.T, conn *frameRecordingConn, passphrase []byte) error {
				conn.readFunc = func(s *stubAdminProtocolConn) ([]byte, error) {
					sent, ok := s.firstWrite()
					if !ok || s.readIndex > 0 {
						return nil, errors.New("no more messages")
					}
					s.readIndex++
					return mustMarshalProtocolMessage(t, protocol.UnlockResultMessage{
						BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeUnlockResult, ID: sent.(protocol.UnlockMessage).ID},
						Success:     true,
					}), nil
				}
				_, err := unlockWithDispatcher(newDispatcher(conn), passphrase, 5*time.Second)
				return err
			},
			sent: func(v interface{}) protocol.SensitiveBytes { return v.(protocol.UnlockMessage).Passphrase },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &frameRecordingConn{}
			passphrase := []byte("request-secret")
			if err := tt.run(t, conn, passphrase); err != nil {
				t.Fatalf("request error = %v", err)
			}
			sent, ok := conn.firstWrite()
			if !ok || len(conn.frames) != 1 {
				t.Fatalf("request wrote %d frames", len(conn.frames))
			}
			var frame struct {
				Passphrase string `json:"passphrase"`
			}
			if err := json.Unmarshal(conn.frames[0], &frame); err != nil || frame.Passphrase != "request-secret" {
				t.Fatalf("frame passphrase = %q (%v), want the caller's", frame.Passphrase, err)
			}
			if copied := tt.sent(sent); !isZeroed(copied) {
				t.Fatalf("message copy left as %q after the request", []byte(copied))
			}
			if string(passphrase) != "request-secret" {
				t.Fatalf("request changed the caller's buffer to %q", passphrase)
			}
		})
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

// A strict dispatcher drops, and zeroes, the late reply to a request that
// timed out: its caller already has the timeout, and the connection stays up
// for the next request.
func TestStrictDispatcherDropsTheLateReplyToATimedOutRequest(t *testing.T) {
	reply := func(id string) []byte {
		return mustMarshalProtocolMessage(t, protocol.KeysListMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeKeysList, ID: id},
			Keys:        []protocol.AdminKeyInfo{},
		})
	}
	request := func(id string) protocol.ListKeysMessage {
		return protocol.ListKeysMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListKeys, ID: id}}
	}
	timedOut, done := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(done) })
	late := reply("keys-slow")
	conn := &stubAdminProtocolConn{readFunc: func(s *stubAdminProtocolConn) ([]byte, error) {
		s.mu.Lock()
		index := s.readIndex
		s.readIndex++
		s.mu.Unlock()
		switch index {
		case 0:
			<-timedOut
			return late, nil
		case 1:
			for s.writeCount() < 2 {
				time.Sleep(time.Millisecond)
			}
			return reply("keys-next"), nil
		default:
			<-done
			return nil, errors.New("test over")
		}
	}}
	dispatcher := newDispatcher(conn)

	if _, err := dispatcher.request(request("keys-slow"), 20*time.Millisecond); err == nil {
		t.Fatal("slow request did not time out")
	}
	close(timedOut)
	if _, err := dispatcher.request(request("keys-next"), 5*time.Second); err != nil {
		t.Fatalf("request after the late reply failed: %v", err)
	}
	if !isZeroed(late) {
		t.Fatalf("dropped late reply left as %q", late)
	}
	select {
	case event := <-dispatcher.lifecycleChan():
		t.Fatalf("late reply ended the connection: %v %v", event.Type, event.Err)
	default:
	}
}

// A reply nobody asked for still ends a strict connection, and its frame is
// zeroed first.
func TestStrictDispatcherZeroesAnUnmatchedReplyBeforeFailing(t *testing.T) {
	unmatched := mustMarshalProtocolMessage(t, protocol.KeysListMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeKeysList, ID: "never-sent"},
		Keys:        []protocol.AdminKeyInfo{},
	})
	conn := &stubAdminProtocolConn{reads: [][]byte{unmatched}}
	dispatcher := newDispatcher(conn)
	_, err := dispatcher.request(protocol.ListKeysMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListKeys, ID: "keys-1"},
	}, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "without pending waiter") {
		t.Fatalf("request error = %v, want the unmatched-reply failure", err)
	}
	if !isZeroed(unmatched) {
		t.Fatalf("unmatched reply left as %q", unmatched)
	}
}
