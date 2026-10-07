// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// serveConnections hands every accepted socket to the full connection path.
func serveConnections(t *testing.T, srv *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			srv.activeConns.Add(1)
			go srv.handleConnection(conn)
		}
	}()
	return ln.Addr().String()
}

func dialEnrollment(t *testing.T, srv *Server, addr string) *ssh.Client {
	t.Helper()
	signer, _ := generateClientKey(t)
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            enrollmentSSHUsername,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(srv.hostKey.PublicKey()),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial request-enrollment: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func closedWithin(client *ssh.Client, d time.Duration) bool {
	done := make(chan struct{})
	go func() { _ = client.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// A connection may request once: the connection closes when its request has
// been answered, so a client cannot hold a connection slot or submit again
// on it.
func TestEnrollmentConnectionRequestsOnce(t *testing.T) {
	srv, _ := testServer(t)
	setEnrollmentHooks(srv, EnrollmentHooks{Request: pendingHook(nil)})
	client := dialEnrollment(t, srv, serveConnections(t, srv))

	first, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := first.CombinedOutput("enroll")
	if err != nil || !strings.HasPrefix(string(out), "pending ") {
		t.Fatalf("first request = %q, %v; want a pending answer", out, err)
	}
	if !closedWithin(client, 2*time.Second) {
		t.Fatal("enrollment connection stayed open after its request was answered")
	}
}

// A enrollment connection that never starts provisioning is closed.
func TestIdleEnrollmentConnectionIsClosed(t *testing.T) {
	srv, _ := testServer(t)
	srv.enrollmentExecDeadline = 100 * time.Millisecond
	setEnrollmentHooks(srv, EnrollmentHooks{
		Request: pendingHook(nil),
	})
	client := dialEnrollment(t, srv, serveConnections(t, srv))
	if !closedWithin(client, 2*time.Second) {
		t.Fatal("idle enrollment connection stayed open past its deadline")
	}
}

// Live enrollment connections are capped.
func TestEnrollmentConnectionsAreCapped(t *testing.T) {
	srv, _ := testServer(t)
	setEnrollmentHooks(srv, EnrollmentHooks{
		Request: pendingHook(nil),
	})
	addr := serveConnections(t, srv)
	for i := 0; i < maxEnrollmentConns; i++ {
		dialEnrollment(t, srv, addr)
	}
	waitFor := time.Now().Add(2 * time.Second)
	for time.Now().Before(waitFor) {
		srv.sshConnsMu.Lock()
		n := srv.enrollmentConns
		srv.sshConnsMu.Unlock()
		if n == maxEnrollmentConns {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	extra := dialEnrollment(t, srv, addr)
	if !closedWithin(extra, 2*time.Second) {
		t.Fatalf("enrollment connection %d beyond the cap stayed open", maxEnrollmentConns+1)
	}
}

// stalledChannel models a client that never extends its receive window: a
// write blocks until the connection closes.
type stalledChannel struct {
	ssh.Channel
	closed chan struct{}
}

func (c *stalledChannel) Write([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}

type closeRecordingConn struct {
	ssh.Conn
	closed chan struct{}
}

func (c *closeRecordingConn) Close() error {
	close(c.closed)
	return nil
}

// A client that stops reading cannot hold the provisioning slot: the response
// deadline closes its connection, which fails the blocked write.
func TestEnrollmentReplyToStalledClientTimesOut(t *testing.T) {
	srv, _ := testServer(t)
	srv.enrollmentRespDeadline = 50 * time.Millisecond
	closed := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- srv.respondEnrollment(&closeRecordingConn{closed: closed}, &stalledChannel{closed: closed}, "ERROR: rejected\n", 1)
	}()
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("respondEnrollment() error = %v, want the write to fail", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("response write to a stalled client blocked past its deadline")
	}
}

// A enrollment connection cannot open channels without bound: channels
// beyond the cap are rejected before a handler is started.
func TestEnrollmentChannelsAreCapped(t *testing.T) {
	srv, _ := testServer(t)
	setEnrollmentHooks(srv, EnrollmentHooks{
		Request: pendingHook(nil),
	})
	client := dialEnrollment(t, srv, serveConnections(t, srv))
	for i := 0; i < maxEnrollmentChannels; i++ {
		if _, err := client.NewSession(); err != nil {
			t.Fatalf("session %d: %v", i+1, err)
		}
	}
	if _, err := client.NewSession(); err == nil || !strings.Contains(err.Error(), "too many channels") {
		t.Fatalf("session beyond the cap error = %v, want a rejection", err)
	}
}

// Unauthenticated client text is quoted and truncated before it is logged,
// so terminal escapes cannot reach an operator's console.
func TestQuoteClientTextEscapesAndTruncates(t *testing.T) {
	if got := quoteClientText("\x1b[2Jfake\nline"); strings.ContainsAny(got, "\x1b\n") {
		t.Fatalf("quoteClientText() = %q, want control characters escaped", got)
	}
	if got := quoteClientText(strings.Repeat("a", 500)); len(got) > maxLoggedClientTextBytes+8 {
		t.Fatalf("quoteClientText() length = %d, want it truncated", len(got))
	}
}
