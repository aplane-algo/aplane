// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

type fakeSession struct {
	dialErr         error
	authErr         error
	authOnlyErr     error
	status          protocol.StatusMessage
	statusErr       error
	unlock          protocol.UnlockResultMessage
	unlockErr       error
	response        []byte
	requestErr      error
	dialed          int
	closed          int
	authenticated   int
	authenticatedRO int
	statusReads     int
	unlocks         int
	requests        int
	passphrase      string
	// received keeps every passphrase slice the session was handed, uncopied.
	received [][]byte
}

func (s *fakeSession) Dial() error { s.dialed++; return s.dialErr }
func (s *fakeSession) Close()      { s.closed++ }
func (s *fakeSession) Authenticate(passphrase []byte, _ time.Duration) error {
	s.authenticated++
	s.passphrase = string(passphrase)
	s.received = append(s.received, passphrase)
	return s.authErr
}
func (s *fakeSession) AuthenticateOnly(passphrase []byte, _ time.Duration) error {
	s.authenticatedRO++
	s.passphrase = string(passphrase)
	s.received = append(s.received, passphrase)
	return s.authOnlyErr
}
func (s *fakeSession) WaitForStatus(time.Duration) (*protocol.StatusMessage, error) {
	s.statusReads++
	return &s.status, s.statusErr
}
func (s *fakeSession) Unlock(passphrase []byte, _ time.Duration) (*protocol.UnlockResultMessage, error) {
	s.unlocks++
	s.passphrase = string(passphrase)
	s.received = append(s.received, passphrase)
	return &s.unlock, s.unlockErr
}
func (s *fakeSession) SendAndReceive(interface{}, time.Duration) ([]byte, error) {
	s.requests++
	return s.response, s.requestErr
}

func TestOpenReadOnlyNeverReadsStatusOrUnlocks(t *testing.T) {
	session := &fakeSession{}
	client, err := Open(session, []byte("secret"), AuthReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	if session.authenticatedRO != 1 || session.authenticated != 0 || session.statusReads != 0 || session.unlocks != 0 {
		t.Fatalf("read-only session calls = %+v", session)
	}
	if session.closed != 1 {
		t.Fatalf("Close calls = %d, want 1", session.closed)
	}
}

func TestOpenUnlocksOnlyLockedRuntime(t *testing.T) {
	for _, state := range []string{"unlocked", "locked"} {
		t.Run(state, func(t *testing.T) {
			session := &fakeSession{
				status: protocol.StatusMessage{State: state},
				unlock: protocol.UnlockResultMessage{Success: true},
			}
			client, err := Open(session, []byte("secret"), AuthUnlock)
			if err != nil {
				t.Fatal(err)
			}
			client.Close()
			wantUnlocks := 0
			if state == "locked" {
				wantUnlocks = 1
			}
			if session.authenticated != 1 || session.authenticatedRO != 0 || session.statusReads != 1 || session.unlocks != wantUnlocks {
				t.Fatalf("session calls = %+v", session)
			}
		})
	}
}

// Open hands the session the caller's passphrase bytes and makes no copy of
// them, so the caller's zeroing clears every passphrase the login and the
// unlock were given.
func TestOpenLeavesNoPassphraseCopyBehind(t *testing.T) {
	for _, mode := range []AuthMode{AuthReadOnly, AuthUnlock} {
		session := &fakeSession{
			status: protocol.StatusMessage{State: "locked"},
			unlock: protocol.UnlockResultMessage{Success: true},
		}
		passphrase := []byte("secret")
		client, err := Open(session, passphrase, mode)
		if err != nil {
			t.Fatal(err)
		}
		client.Close()
		want := 1
		if mode == AuthUnlock {
			want = 2
		}
		if len(session.received) != want {
			t.Fatalf("mode %d: session got %d passphrases, want %d", mode, len(session.received), want)
		}
		clear(passphrase)
		for i, got := range session.received {
			if !bytes.Equal(got, make([]byte, len("secret"))) {
				t.Fatalf("mode %d: passphrase %d the session got is %q after the caller zeroed its own", mode, i, got)
			}
		}
	}
}

func TestOpenClosesEveryFailedSetup(t *testing.T) {
	tests := []struct {
		name    string
		session *fakeSession
		mode    AuthMode
	}{
		{name: "read-only auth", session: &fakeSession{authOnlyErr: errors.New("denied")}, mode: AuthReadOnly},
		{name: "auth", session: &fakeSession{authErr: errors.New("denied")}, mode: AuthUnlock},
		{name: "status", session: &fakeSession{statusErr: errors.New("closed")}, mode: AuthUnlock},
		{name: "unlock", session: &fakeSession{status: protocol.StatusMessage{State: "locked"}, unlockErr: errors.New("denied")}, mode: AuthUnlock},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Open(tt.session, []byte("secret"), tt.mode); err == nil {
				t.Fatal("Open() error = nil")
			}
			if tt.session.closed != 1 {
				t.Fatalf("Close calls = %d, want 1", tt.session.closed)
			}
		})
	}
}

func TestRequestPreservesProtocolErrorCode(t *testing.T) {
	raw, err := json.Marshal(protocol.ErrorMessage{
		BaseMessage: protocol.BaseMessage{Kind: protocol.MessageKindResponse, Type: protocol.MsgTypeError},
		Code:        protocol.ResultCodeStoreBusy,
		Error:       "store is busy",
	})
	if err != nil {
		t.Fatal(err)
	}
	session := &fakeSession{response: raw}
	client := &Client{session: session, timeout: time.Second}
	var result protocol.GenerationsListMessage
	err = client.Request(struct{}{}, &result)
	if got := protocol.CodeForError(err); got != protocol.ResultCodeStoreBusy {
		t.Fatalf("Request() code = %q error = %v, want store_busy", got, err)
	}
}
