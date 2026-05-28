// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package transport

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

type stubAdminProtocolConn struct {
	mu             sync.Mutex
	writes         []interface{}
	writeErr       error
	reads          [][]byte
	readErr        error
	readIndex      int
	setDeadlineFor time.Duration
	clearCalled    bool
	readFunc       func(*stubAdminProtocolConn) ([]byte, error)
}

func (s *stubAdminProtocolConn) WriteJSON(v interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeErr != nil {
		return s.writeErr
	}
	s.writes = append(s.writes, v)
	return nil
}

func (s *stubAdminProtocolConn) ReadMessage() ([]byte, error) {
	if s.readFunc != nil {
		return s.readFunc(s)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readIndex >= len(s.reads) {
		if s.readErr != nil {
			return nil, s.readErr
		}
		return nil, errors.New("no more messages")
	}
	msg := s.reads[s.readIndex]
	s.readIndex++
	return msg, nil
}

func (s *stubAdminProtocolConn) SetReadDeadline(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setDeadlineFor = d
}

func (s *stubAdminProtocolConn) ClearReadDeadline() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearCalled = true
}

func (s *stubAdminProtocolConn) writeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.writes)
}

func (s *stubAdminProtocolConn) firstWrite() (interface{}, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.writes) == 0 {
		return nil, false
	}
	return s.writes[0], true
}

func TestDispatcherRequestKeepsNotificationsWhileWaiting(t *testing.T) {
	request := protocol.GenerateKeyMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeGenerateKey,
			ID:   "gen-123",
		},
		KeyType: "ed25519",
	}
	keysChanged := mustMarshalProtocolMessage(t, protocol.KeysChangedMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeKeysChanged},
		KeyCount:    1,
	})
	result := mustMarshalProtocolMessage(t, protocol.GenerateResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeGenerateResult,
			ID:   "gen-123",
		},
		Success: true,
		Address: "ADDR",
	})

	conn := &stubAdminProtocolConn{
		reads: [][]byte{keysChanged},
		readFunc: func(s *stubAdminProtocolConn) ([]byte, error) {
			for {
				s.mu.Lock()
				if s.readIndex < len(s.reads) {
					msg := s.reads[s.readIndex]
					s.readIndex++
					s.mu.Unlock()
					return msg, nil
				}
				writes := len(s.writes)
				s.mu.Unlock()
				if writes == 1 {
					return result, nil
				}
				time.Sleep(time.Millisecond)
			}
		},
	}
	dispatcher := newDispatcher(conn)
	notifications := dispatcher.notificationsChan()

	response, err := dispatcher.request(request, 5*time.Second)
	if err != nil {
		t.Fatalf("dispatcher.request() error = %v", err)
	}
	if string(response) != string(result) {
		t.Fatalf("dispatcher.request() returned %s, want %s", response, result)
	}
	if got := conn.writeCount(); got != 1 {
		t.Fatalf("WriteJSON() calls = %d, want 1", got)
	}

	select {
	case notification := <-notifications:
		if notification.Base.Type != protocol.MsgTypeKeysChanged {
			t.Fatalf("notification type = %q, want %q", notification.Base.Type, protocol.MsgTypeKeysChanged)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for notification")
	}
}

func TestDispatcherRequestKeepsMultipleNotificationsWhileWaiting(t *testing.T) {
	request := protocol.GenerateKeyMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeGenerateKey,
			ID:   "gen-456",
		},
		KeyType: "ed25519",
	}
	keysChanged := mustMarshalProtocolMessage(t, protocol.KeysChangedMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeKeysChanged},
		KeyCount:    2,
	})
	status := mustMarshalProtocolMessage(t, protocol.StatusMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeStatus},
		State:       "unlocked",
		KeyCount:    2,
	})
	result := mustMarshalProtocolMessage(t, protocol.GenerateResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeGenerateResult,
			ID:   "gen-456",
		},
		Success: true,
		Address: "ADDR2",
	})

	conn := &stubAdminProtocolConn{
		reads: [][]byte{keysChanged, status},
		readFunc: func(s *stubAdminProtocolConn) ([]byte, error) {
			for {
				s.mu.Lock()
				if s.readIndex < len(s.reads) {
					msg := s.reads[s.readIndex]
					s.readIndex++
					s.mu.Unlock()
					return msg, nil
				}
				writes := len(s.writes)
				s.mu.Unlock()
				if writes == 1 {
					return result, nil
				}
				time.Sleep(time.Millisecond)
			}
		},
	}
	dispatcher := newDispatcher(conn)
	notifications := dispatcher.notificationsChan()

	response, err := dispatcher.request(request, time.Second)
	if err != nil {
		t.Fatalf("dispatcher.request() error = %v", err)
	}
	if string(response) != string(result) {
		t.Fatalf("dispatcher.request() returned %s, want %s", response, result)
	}

	var gotTypes []string
	for i := 0; i < 2; i++ {
		select {
		case notification := <-notifications:
			gotTypes = append(gotTypes, notification.Base.Type)
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for notification %d", i+1)
		}
	}
	if gotTypes[0] != protocol.MsgTypeKeysChanged || gotTypes[1] != protocol.MsgTypeStatus {
		t.Fatalf("notification types = %v, want [%s %s]", gotTypes, protocol.MsgTypeKeysChanged, protocol.MsgTypeStatus)
	}
}

func TestDispatcherRequestRejectsUnexpectedResponseID(t *testing.T) {
	request := protocol.DeleteKeyMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeDeleteKey,
			ID:   "del-2",
		},
		Address: "ADDR",
	}
	otherResult := mustMarshalProtocolMessage(t, protocol.DeleteResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeDeleteResult,
			ID:   "del-1",
		},
		Success: true,
	})

	conn := &stubAdminProtocolConn{reads: [][]byte{otherResult}}
	dispatcher := newDispatcher(conn)

	_, err := dispatcher.request(request, time.Second)
	if err == nil {
		t.Fatal("dispatcher.request() error = nil, want protocol error")
	}
	if !strings.Contains(err.Error(), "unexpected response message without pending waiter") {
		t.Fatalf("dispatcher.request() error = %q, want unexpected-message protocol error", err)
	}
}

func TestDispatcherNonStrictRoutesUnmatchedResponseToNotifications(t *testing.T) {
	response := mustMarshalProtocolMessage(t, protocol.AuthResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeAuthResult,
			ID:   "auth-1",
		},
		Success: true,
	})

	conn := &stubAdminProtocolConn{reads: [][]byte{response}}
	// Non-strict mode keeps the stale response from the timed-out request
	// from racing the replacement request and closing the dispatcher.
	dispatcher := newDispatcherWithMode(conn, false)

	select {
	case notification := <-dispatcher.notificationsChan():
		if notification.Base.Kind != protocol.MessageKindResponse {
			t.Fatalf("notification kind = %q, want %q", notification.Base.Kind, protocol.MessageKindResponse)
		}
		if notification.Base.Type != protocol.MsgTypeAuthResult {
			t.Fatalf("notification type = %q, want %q", notification.Base.Type, protocol.MsgTypeAuthResult)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for response notification")
	}
}

func TestUnlockWithDispatcherSkipsNotificationAndParsesResult(t *testing.T) {
	keysChanged := mustMarshalProtocolMessage(t, protocol.KeysChangedMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeKeysChanged},
		KeyCount:    3,
	})
	conn := &stubAdminProtocolConn{
		reads: [][]byte{keysChanged},
		readFunc: func(s *stubAdminProtocolConn) ([]byte, error) {
			if s.readIndex < len(s.reads) {
				msg := s.reads[s.readIndex]
				s.readIndex++
				return msg, nil
			}
			if s.writeCount() != 1 {
				return nil, errors.New("unlock request was not written")
			}
			firstWrite, ok := s.firstWrite()
			if !ok {
				return nil, errors.New("unlock request was not written")
			}
			unlockMsg, ok := firstWrite.(protocol.UnlockMessage)
			if !ok {
				return nil, errors.New("unexpected request type")
			}
			return mustMarshalProtocolMessage(t, protocol.UnlockResultMessage{
				BaseMessage: protocol.BaseMessage{
					Type: protocol.MsgTypeUnlockResult,
					ID:   unlockMsg.ID,
				},
				Success:  true,
				KeyCount: 3,
			}), nil
		},
	}
	dispatcher := newDispatcher(conn)

	got, err := unlockWithDispatcher(dispatcher, "secret", 5*time.Second)
	if err != nil {
		t.Fatalf("unlockWithDispatcher() error = %v", err)
	}
	if !got.Success || got.KeyCount != 3 {
		t.Fatalf("unlockWithDispatcher() = %+v, want success with key_count=3", got)
	}
}

func TestDispatcherRequestConnectionLossUnblocksWaiterAndEmitsLifecycle(t *testing.T) {
	request := protocol.ListKeysMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeListKeys,
			ID:   "keys-1",
		},
	}
	conn := &stubAdminProtocolConn{
		readFunc: func(s *stubAdminProtocolConn) ([]byte, error) {
			for {
				if s.writeCount() == 1 {
					return nil, errors.New("connection lost")
				}
				time.Sleep(time.Millisecond)
			}
		},
	}
	dispatcher := newDispatcher(conn)
	lifecycle := dispatcher.lifecycleChan()

	_, err := dispatcher.request(request, time.Second)
	if err == nil {
		t.Fatal("dispatcher.request() error = nil, want connection loss")
	}
	if !strings.Contains(err.Error(), "connection lost") {
		t.Fatalf("dispatcher.request() error = %q, want connection lost", err)
	}

	select {
	case event := <-lifecycle:
		if event.Type != LifecycleConnectionLost {
			t.Fatalf("lifecycle event type = %q, want %q", event.Type, LifecycleConnectionLost)
		}
		if event.Err == nil || !strings.Contains(event.Err.Error(), "connection lost") {
			t.Fatalf("lifecycle event err = %v, want connection lost", event.Err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for connection_lost lifecycle event")
	}

	select {
	case event := <-lifecycle:
		if event.Type != LifecycleReaderStopped {
			t.Fatalf("lifecycle event type = %q, want %q", event.Type, LifecycleReaderStopped)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for reader_stopped lifecycle event")
	}
}

func TestDispatcherRequestRejectsDuplicatePendingID(t *testing.T) {
	request := protocol.ListKeysMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeListKeys,
			ID:   "keys-dup",
		},
	}
	responseReady := make(chan struct{})
	conn := &stubAdminProtocolConn{
		readFunc: func(s *stubAdminProtocolConn) ([]byte, error) {
			<-responseReady
			return mustMarshalProtocolMessage(t, protocol.KeysListMessage{
				BaseMessage: protocol.BaseMessage{
					Type: protocol.MsgTypeKeysList,
					ID:   "keys-dup",
				},
				Keys: []protocol.KeyInfo{{Address: "ADDR1", KeyType: "ed25519"}},
			}), nil
		},
	}
	dispatcher := newDispatcher(conn)

	firstDone := make(chan error, 1)
	go func() {
		_, err := dispatcher.request(request, time.Second)
		firstDone <- err
	}()

	deadline := time.Now().Add(time.Second)
	for conn.writeCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for first request write")
		}
		time.Sleep(time.Millisecond)
	}

	_, err := dispatcher.request(request, 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected duplicate request error, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate pending request ID") {
		t.Fatalf("error = %q, want duplicate pending request ID", err.Error())
	}

	close(responseReady)
	if err := <-firstDone; err != nil {
		t.Fatalf("first request error = %v, want nil", err)
	}
}

func TestDispatcherRequestWriteFailureClearsPending(t *testing.T) {
	request := protocol.ListKeysMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeListKeys,
			ID:   "keys-write-fail",
		},
	}
	conn := &stubAdminProtocolConn{writeErr: errors.New("write boom")}
	dispatcher := newDispatcher(conn)

	_, err := dispatcher.request(request, time.Second)
	if err == nil || !strings.Contains(err.Error(), "write boom") {
		t.Fatalf("first request error = %v, want write boom", err)
	}

	conn.mu.Lock()
	conn.writeErr = nil
	conn.reads = [][]byte{mustMarshalProtocolMessage(t, protocol.KeysListMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeKeysList,
			ID:   "keys-write-fail",
		},
		Keys: []protocol.KeyInfo{},
	})}
	conn.mu.Unlock()

	if _, err := dispatcher.request(request, time.Second); err != nil {
		t.Fatalf("second request after write failure error = %v, want nil", err)
	}
}

func TestDispatcherRequestTimeoutClearsPending(t *testing.T) {
	request := protocol.ListKeysMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeListKeys,
			ID:   "keys-timeout",
		},
	}
	releaseRead := make(chan struct{})
	conn := &stubAdminProtocolConn{
		readFunc: func(s *stubAdminProtocolConn) ([]byte, error) {
			<-releaseRead
			return mustMarshalProtocolMessage(t, protocol.KeysListMessage{
				BaseMessage: protocol.BaseMessage{
					Type: protocol.MsgTypeKeysList,
					ID:   "keys-timeout",
				},
				Keys: []protocol.KeyInfo{},
			}), nil
		},
	}
	dispatcher := newDispatcherWithMode(conn, false)

	_, err := dispatcher.request(request, 20*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out waiting for response") {
		t.Fatalf("first request error = %v, want timeout", err)
	}

	close(releaseRead)
	if _, err := dispatcher.request(request, time.Second); err != nil {
		t.Fatalf("second request after timeout error = %v, want nil", err)
	}
}

func TestDispatcherFailAllIsIdempotent(t *testing.T) {
	dispatcher := newDispatcher(&stubAdminProtocolConn{})
	lifecycle := dispatcher.lifecycleChan()

	dispatcher.failAll(dispatcherLifecycleConnectionLost, errors.New("first failure"))
	dispatcher.failAll(dispatcherLifecycleProtocolError, errors.New("second failure"))

	var events []LifecycleType
	for i := 0; i < 2; i++ {
		select {
		case event := <-lifecycle:
			events = append(events, event.Type)
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for lifecycle event %d", i+1)
		}
	}
	if len(events) != 2 || events[0] != LifecycleConnectionLost || events[1] != LifecycleReaderStopped {
		t.Fatalf("events = %v, want [connection_lost reader_stopped]", events)
	}

	select {
	case event := <-lifecycle:
		t.Fatalf("unexpected extra lifecycle event after second failAll(): %+v", event)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestDispatcherReadLoopDoesNotBlockWhenNotificationsFull(t *testing.T) {
	conn := &stubAdminProtocolConn{
		reads: [][]byte{
			mustMarshalProtocolMessage(t, protocol.StatusMessage{
				BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeStatus},
				State:       "unlocked",
			}),
		},
		readErr: errors.New("reader stopped"),
	}
	dispatcher := newDispatcherWithMode(conn, false)
	for i := 0; i < cap(dispatcher.notifications); i++ {
		dispatcher.notifications <- Notification{}
	}

	lifecycle := dispatcher.lifecycleChan()
	select {
	case event := <-lifecycle:
		if event.Type != LifecycleConnectionLost {
			t.Fatalf("first lifecycle event = %q, want %q", event.Type, LifecycleConnectionLost)
		}
	case <-time.After(time.Second):
		t.Fatal("readLoop blocked on a full notification channel")
	}
}

func TestDispatcherFailAllDoesNotBlockWhenLifecycleFull(t *testing.T) {
	dispatcher := newDispatcher(&stubAdminProtocolConn{})
	waiter := make(chan dispatchResult, 1)
	dispatcher.pending["req-1"] = waiter
	for i := 0; i < cap(dispatcher.lifecycle); i++ {
		dispatcher.lifecycle <- LifecycleEvent{Type: LifecycleConnectionLost}
	}

	done := make(chan struct{})
	go func() {
		dispatcher.failAll(dispatcherLifecycleProtocolError, errors.New("protocol stopped"))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failAll blocked on a full lifecycle channel")
	}

	select {
	case result := <-waiter:
		if result.err == nil || !strings.Contains(result.err.Error(), "protocol stopped") {
			t.Fatalf("pending result error = %v, want protocol stopped", result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for pending request failure")
	}
}

func mustMarshalProtocolMessage(t *testing.T, msg interface{}) []byte {
	t.Helper()
	data, err := protocol.MarshalAdminMessage(msg)
	if err != nil {
		t.Fatalf("MarshalAdminMessage() error = %v", err)
	}
	return data
}
