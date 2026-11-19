// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// fakeApproverConn records the passphrase the login sent.
type fakeApproverConn struct {
	dialErr error
	authErr error
	sent    string
	closed  bool
}

func (c *fakeApproverConn) Dial() error { return c.dialErr }

func (c *fakeApproverConn) Authenticate(passphrase []byte, _ time.Duration) error {
	c.sent = string(passphrase)
	return c.authErr
}

func (c *fakeApproverConn) Close() { c.closed = true }

// The passphrase read for the login is zeroed once the login is done, whether
// it succeeded, was refused or never reached the signer.
func TestLoginApproverZeroesThePassphrase(t *testing.T) {
	tests := []struct {
		name     string
		conn     *fakeApproverConn
		ok       bool
		wantSent string
	}{
		{name: "authenticated", conn: &fakeApproverConn{}, ok: true, wantSent: "approver-secret"},
		{name: "refused", conn: &fakeApproverConn{authErr: errors.New("invalid passphrase")}, wantSent: "approver-secret"},
		{name: "dial failed", conn: &fakeApproverConn{dialErr: errors.New("no socket")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var read []byte
			ok := loginApprover(tt.conn, "/run/test.sock", func() ([]byte, error) {
				read = []byte("approver-secret")
				return read, nil
			})
			if ok != tt.ok || tt.conn.sent != tt.wantSent {
				t.Fatalf("login = %v sent %q, want %v sent %q", ok, tt.conn.sent, tt.ok, tt.wantSent)
			}
			if !bytes.Equal(read, make([]byte, len(read))) {
				t.Fatalf("login left the passphrase as %q", read)
			}
		})
	}
}
