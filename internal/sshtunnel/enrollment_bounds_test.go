// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"context"
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

// Only one client access request may be pending server-wide, so an
// unauthenticated client cannot queue a stream of operator prompts.
func TestOnlyOneClientAccessRequestPendsAtATime(t *testing.T) {
	srv, _ := testServer(t)
	started := make(chan struct{})
	release := make(chan struct{})
	setEnrollmentHooks(srv, EnrollmentHooks{
		ApproveContext: func(ctx context.Context, _, _, _ string) (bool, error) {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
			}
			return false, nil
		},
	})
	addr := serveConnections(t, srv)

	first, err := dialEnrollment(t, srv, addr).NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Start("enroll"); err != nil {
		t.Fatal(err)
	}
	<-started

	second, err := dialEnrollment(t, srv, addr).NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, _ := second.CombinedOutput("enroll")
	if !strings.Contains(string(out), "another enrollment request is pending") {
		t.Fatalf("second request output = %q, want a pending-request refusal", out)
	}
	close(release)
}

// A connection may provision once: a concurrent second request on the same
// connection is refused, and the connection closes when its request ends, so
// a refused or rejected client cannot hold a connection slot.
func TestRequestTokenConnectionProvisionsOnce(t *testing.T) {
	srv, _ := testServer(t)
	started := make(chan struct{})
	release := make(chan struct{})
	setEnrollmentHooks(srv, EnrollmentHooks{
		ApproveContext: func(ctx context.Context, _, _, _ string) (bool, error) {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
			}
			return false, nil
		},
	})
	client := dialEnrollment(t, srv, serveConnections(t, srv))

	first, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	var firstOut strings.Builder
	first.Stdout = &firstOut
	if err := first.Start("enroll"); err != nil {
		t.Fatal(err)
	}
	<-started

	second, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, _ := second.CombinedOutput("enroll")
	if !strings.Contains(string(out), "only one enrollment request is allowed per connection") {
		t.Fatalf("second request output = %q, want a per-connection refusal", out)
	}

	close(release)
	_ = first.Wait()
	if !strings.Contains(firstOut.String(), "rejected by operator") {
		t.Fatalf("first request output = %q, want the operator rejection", firstOut.String())
	}
	if !closedWithin(client, 2*time.Second) {
		t.Fatal("enrollment connection stayed open after its provisioning request ended")
	}
}

// A enrollment connection that never starts provisioning is closed.
func TestIdleRequestTokenConnectionIsClosed(t *testing.T) {
	srv, _ := testServer(t)
	srv.enrollmentExecDeadline = 100 * time.Millisecond
	setEnrollmentHooks(srv, EnrollmentHooks{
		ApproveContext: func(context.Context, string, string, string) (bool, error) { return false, nil },
	})
	client := dialEnrollment(t, srv, serveConnections(t, srv))
	if !closedWithin(client, 2*time.Second) {
		t.Fatal("idle enrollment connection stayed open past its deadline")
	}
}

// Live enrollment connections are capped.
func TestRequestTokenConnectionsAreCapped(t *testing.T) {
	srv, _ := testServer(t)
	setEnrollmentHooks(srv, EnrollmentHooks{
		ApproveContext: func(context.Context, string, string, string) (bool, error) { return false, nil },
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
func TestProvisioningResponseToStalledClientTimesOut(t *testing.T) {
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
func TestRequestTokenChannelsAreCapped(t *testing.T) {
	srv, _ := testServer(t)
	setEnrollmentHooks(srv, EnrollmentHooks{
		ApproveContext: func(context.Context, string, string, string) (bool, error) { return false, nil },
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
