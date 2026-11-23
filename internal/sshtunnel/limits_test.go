// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func tryDialAuthenticated(srv *Server, addr string, signer ssh.Signer) (*ssh.Client, error) {
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            productSSHUsername,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(srv.hostKey.PublicKey()),
		Timeout:         5 * time.Second,
	})
}

func dialAuthenticated(t *testing.T, srv *Server, addr string, signer ssh.Signer) *ssh.Client {
	t.Helper()
	client, err := tryDialAuthenticated(srv, addr, signer)
	if err != nil {
		t.Fatalf("ssh.Dial(%s): %v", productSSHUsername, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func totalAuthenticatedCount(srv *Server) int {
	total := 0
	for _, n := range srv.ConnectedFingerprints() {
		total += n
	}
	return total
}

func waitForFingerprintCount(t *testing.T, srv *Server, fingerprint string, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.ConnectedFingerprints()[fingerprint] == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("ConnectedFingerprints()[%s] = %d, want %d", fingerprint, srv.ConnectedFingerprints()[fingerprint], want)
}

func waitForTotalAuthenticatedCount(t *testing.T, srv *Server, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if totalAuthenticatedCount(srv) == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("total authenticated connections = %d, want %d", totalAuthenticatedCount(srv), want)
}

func waitForEnrollmentConnCount(t *testing.T, srv *Server, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		srv.sshConnsMu.Lock()
		n := srv.enrollmentConns
		srv.sshConnsMu.Unlock()
		if n == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	srv.sshConnsMu.Lock()
	got := srv.enrollmentConns
	srv.sshConnsMu.Unlock()
	t.Fatalf("enrollmentConns = %d, want %d", got, want)
}

// One enrolled key may hold at most maxAuthenticatedSSHConnsPerKey live
// connections: excess connections are closed after authentication without
// affecting other enrolled keys, and closing a connection frees its slot.
func TestAuthenticatedConnectionsCappedPerKey(t *testing.T) {
	srv, _ := testServer(t)
	set := newEnrolledSet()
	srv.SetProductHooks(set.hooks())

	var eventsMu sync.Mutex
	var events []SessionEvent
	srv.SetSessionCallback(func(ev SessionEvent) {
		eventsMu.Lock()
		events = append(events, ev)
		eventsMu.Unlock()
	})

	signerA, pubA := generateClientKey(t)
	fpA := ssh.FingerprintSHA256(pubA)
	signerB, pubB := generateClientKey(t)
	fpB := ssh.FingerprintSHA256(pubB)
	set.add(pubA)
	set.add(pubB)

	addr := serveConnections(t, srv)

	connsA := make([]*ssh.Client, 0, maxAuthenticatedSSHConnsPerKey)
	for i := 0; i < maxAuthenticatedSSHConnsPerKey; i++ {
		connsA = append(connsA, dialAuthenticated(t, srv, addr, signerA))
	}
	waitForFingerprintCount(t, srv, fpA, maxAuthenticatedSSHConnsPerKey)

	// Connection beyond key A's limit must be refused and closed promptly
	// without registering a session event.
	extraA, err := tryDialAuthenticated(srv, addr, signerA)
	if err == nil {
		defer func() { _ = extraA.Close() }()
		if !closedWithin(extraA, 2*time.Second) {
			t.Fatalf("connection %d beyond per-key cap stayed open", maxAuthenticatedSSHConnsPerKey+1)
		}
	}
	if got := srv.ConnectedFingerprints()[fpA]; got != maxAuthenticatedSSHConnsPerKey {
		t.Fatalf("ConnectedFingerprints()[keyA] = %d, want %d", got, maxAuthenticatedSSHConnsPerKey)
	}
	eventsMu.Lock()
	connectEventsA := 0
	for _, ev := range events {
		if ev.Fingerprint == fpA && ev.Connected {
			connectEventsA++
		}
	}
	eventsMu.Unlock()
	if connectEventsA != maxAuthenticatedSSHConnsPerKey {
		t.Fatalf("keyA connected session events = %d, want %d (refused connection must not register)", connectEventsA, maxAuthenticatedSSHConnsPerKey)
	}

	// Another enrolled key does not share key A's per-key limit.
	connB := dialAuthenticated(t, srv, addr, signerB)
	waitForFingerprintCount(t, srv, fpB, 1)
	if closedWithin(connB, 100*time.Millisecond) {
		t.Fatal("distinct enrolled key was closed while another key was at its per-key cap")
	}

	// Closing one of key A's connections frees its slot.
	_ = connsA[0].Close()
	waitForFingerprintCount(t, srv, fpA, maxAuthenticatedSSHConnsPerKey-1)

	replacementA := dialAuthenticated(t, srv, addr, signerA)
	waitForFingerprintCount(t, srv, fpA, maxAuthenticatedSSHConnsPerKey)
	if closedWithin(replacementA, 100*time.Millisecond) {
		t.Fatal("replacement connection after freeing a per-key slot was closed")
	}
}

// When the server refuses an authenticated connection for hitting a connection
// limit, it sends ConnectionLimitRequestType before closing so sshtunnel.Client
// records DisconnectReasonConnectionLimit and logs the limit warning instead of
// a plain remote close.
func TestClientObservesConnectionLimitDisconnectReason(t *testing.T) {
	out := captureLog(t)
	srv, tmpDir := testServer(t)
	set := newEnrolledSet()
	srv.SetProductHooks(set.hooks())

	_, pub, identityPath := generateClientIdentityFile(t, tmpDir)
	fp := ssh.FingerprintSHA256(pub)
	set.add(pub)
	host, port, known := startServer(t, srv, tmpDir)

	for i := 0; i < maxAuthenticatedSSHConnsPerKey; i++ {
		c := NewClient(host, port, identityPath, known)
		if err := c.ConnectWithKey(context.Background()); err != nil {
			t.Fatalf("ConnectWithKey(%d) error = %v", i+1, err)
		}
		t.Cleanup(func() { _ = c.Close() })
	}
	waitForFingerprintCount(t, srv, fp, maxAuthenticatedSSHConnsPerKey)

	extra := NewClient(host, port, identityPath, known)
	t.Cleanup(func() { _ = extra.Close() })
	disconnected := make(chan struct{})
	extra.SetDisconnectCallback(func() { close(disconnected) })
	if err := extra.ConnectWithKey(context.Background()); err != nil {
		t.Fatalf("extra ConnectWithKey() error = %v, want handshake to succeed before post-auth limit close", err)
	}
	select {
	case <-disconnected:
	case <-time.After(3 * time.Second):
		t.Fatal("excess client connection was not disconnected")
	}
	if got := extra.DisconnectReason(); got != DisconnectReasonConnectionLimit {
		t.Fatalf("DisconnectReason() = %q, want %q", got, DisconnectReasonConnectionLimit)
	}
	if !strings.Contains(out.String(), "signer connection limit reached") {
		t.Fatalf("client log = %q, want signer connection limit warning", out.String())
	}
}

// Total live authenticated connections across all enrolled keys are capped at
// maxAuthenticatedSSHConns, independently of enrollment connections, and
// closing any authenticated connection frees a slot.
func TestAuthenticatedConnectionsCappedInTotal(t *testing.T) {
	srv, _ := testServer(t)
	set := newEnrolledSet()
	srv.SetProductHooks(set.hooks())
	setEnrollmentHooks(srv, EnrollmentHooks{Request: pendingHook(nil)})

	addr := serveConnections(t, srv)

	// Open an enrollment connection before filling the authenticated cap so
	// we also prove enrollment connections do not consume authenticated slots.
	earlyEnroll := dialEnrollment(t, srv, addr)
	waitForEnrollmentConnCount(t, srv, 1)
	if closedWithin(earlyEnroll, 50*time.Millisecond) {
		t.Fatal("early enrollment connection closed unexpectedly")
	}

	var opened []*ssh.Client
	for remaining := maxAuthenticatedSSHConns; remaining > 0; {
		signer, pub := generateClientKey(t)
		set.add(pub)
		batch := maxAuthenticatedSSHConnsPerKey
		if batch > remaining {
			batch = remaining
		}
		for i := 0; i < batch; i++ {
			opened = append(opened, dialAuthenticated(t, srv, addr, signer))
		}
		remaining -= batch
	}
	waitForTotalAuthenticatedCount(t, srv, maxAuthenticatedSSHConns)

	// A fresh enrolled key with 0 connections of its own is still refused
	// once the server-wide authenticated connection cap is reached.
	overflowSigner, overflowPub := generateClientKey(t)
	overflowFP := ssh.FingerprintSHA256(overflowPub)
	set.add(overflowPub)
	overflowConn, err := tryDialAuthenticated(srv, addr, overflowSigner)
	if err == nil {
		defer func() { _ = overflowConn.Close() }()
		if !closedWithin(overflowConn, 2*time.Second) {
			t.Fatalf("authenticated connection %d beyond total cap stayed open", maxAuthenticatedSSHConns+1)
		}
	}
	if got := srv.ConnectedFingerprints()[overflowFP]; got != 0 {
		t.Fatalf("overflow key count = %d, want 0", got)
	}

	// Enrollment connections use their own cap and are not blocked by full
	// authenticated slots.
	enrollClient := dialEnrollment(t, srv, addr)
	if closedWithin(enrollClient, 100*time.Millisecond) {
		t.Fatal("enrollment connection was closed because authenticated connections were at cap")
	}

	// Closing one authenticated connection frees a slot for the fresh key.
	_ = opened[0].Close()
	waitForTotalAuthenticatedCount(t, srv, maxAuthenticatedSSHConns-1)

	admitted := dialAuthenticated(t, srv, addr, overflowSigner)
	waitForFingerprintCount(t, srv, overflowFP, 1)
	if closedWithin(admitted, 100*time.Millisecond) {
		t.Fatal("connection after freeing a total authenticated slot was closed")
	}
}

// Each authenticated SSH connection may hold at most
// maxDirectTCPIPChannelsPerConn open direct-tcpip channels: excess channels
// are rejected with ssh.ResourceShortage before reaching apiHandoff, other
// connections keep their own budget, and closing a channel frees its slot.
func TestDirectTCPIPChannelsCappedPerConnection(t *testing.T) {
	srv, tmpDir := testServer(t)
	set := newEnrolledSet()
	srv.SetProductHooks(set.hooks())

	var handoffCalls atomic.Int32
	closedAPIs := make(chan struct{}, maxDirectTCPIPChannelsPerConn+4)
	srv.SetAPIHandoff(func(conn *APIConn) error {
		handoffCalls.Add(1)
		go func() {
			defer func() {
				_ = conn.Close()
				closedAPIs <- struct{}{}
			}()
			_, _ = io.Copy(io.Discard, conn)
		}()
		return nil
	})

	host, port, known := startServer(t, srv, tmpDir)
	clientA, _ := connectEnrolledClient(t, srv, set, tmpDir, host, port, known)
	clientB, _ := connectEnrolledClient(t, srv, set, tmpDir, host, port, known)

	conns := make([]net.Conn, 0, maxDirectTCPIPChannelsPerConn)
	for i := 0; i < maxDirectTCPIPChannelsPerConn; i++ {
		c, err := clientA.DialSignerAPI(context.Background())
		if err != nil {
			t.Fatalf("DialSignerAPI(%d) error = %v", i+1, err)
		}
		t.Cleanup(func() { _ = c.Close() })
		conns = append(conns, c)
	}

	beforeExcess := handoffCalls.Load()
	_, err := clientA.DialSignerAPI(context.Background())
	var openErr *ssh.OpenChannelError
	if !errors.As(err, &openErr) || openErr.Reason != ssh.ResourceShortage {
		t.Fatalf("DialSignerAPI(excess) error = %v, want ssh.OpenChannelError{Reason: ResourceShortage}", err)
	}
	if got := handoffCalls.Load(); got != beforeExcess {
		t.Fatalf("excess channel reached apiHandoff: calls = %d, want %d", got, beforeExcess)
	}

	// Another connection keeps its own per-connection channel budget.
	connB, err := clientB.DialSignerAPI(context.Background())
	if err != nil {
		t.Fatalf("second connection DialSignerAPI() error = %v", err)
	}
	t.Cleanup(func() { _ = connB.Close() })

	// Closing an open channel frees its slot on clientA.
	_ = conns[0].Close()
	select {
	case <-closedAPIs:
	case <-time.After(2 * time.Second):
		t.Fatal("closed channel did not tear down its API connection")
	}

	var replacement net.Conn
	deadline := time.Now().Add(2 * time.Second)
	for {
		replacement, err = clientA.DialSignerAPI(context.Background())
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("DialSignerAPI() after closing a channel failed: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Cleanup(func() { _ = replacement.Close() })
}

// A burst of simultaneous direct-tcpip opens on one connection must not slip
// past maxDirectTCPIPChannelsPerConn: accounting happens in the channel accept
// loop before spawning each handler goroutine.
func TestDirectTCPIPChannelsConcurrentBurstEnforcesCap(t *testing.T) {
	srv, tmpDir := testServer(t)
	set := newEnrolledSet()
	srv.SetProductHooks(set.hooks())

	var handoffCalls atomic.Int32
	srv.SetAPIHandoff(func(conn *APIConn) error {
		handoffCalls.Add(1)
		go func() {
			defer func() { _ = conn.Close() }()
			_, _ = io.Copy(io.Discard, conn)
		}()
		return nil
	})

	host, port, known := startServer(t, srv, tmpDir)
	client, _ := connectEnrolledClient(t, srv, set, tmpDir, host, port, known)

	const burst = maxDirectTCPIPChannelsPerConn * 2
	start := make(chan struct{})
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		opened   []net.Conn
		rejected int
		otherErr []error
	)
	wg.Add(burst)
	for i := 0; i < burst; i++ {
		go func() {
			defer wg.Done()
			<-start
			conn, err := client.DialSignerAPI(context.Background())
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				opened = append(opened, conn)
				return
			}
			var openErr *ssh.OpenChannelError
			if errors.As(err, &openErr) && openErr.Reason == ssh.ResourceShortage {
				rejected++
				return
			}
			otherErr = append(otherErr, err)
		}()
	}
	close(start)
	wg.Wait()
	for _, c := range opened {
		t.Cleanup(func() { _ = c.Close() })
	}

	if len(otherErr) > 0 {
		t.Fatalf("unexpected channel errors: %v", otherErr)
	}
	if len(opened) != maxDirectTCPIPChannelsPerConn {
		t.Fatalf("concurrent burst opened %d channels, want %d (rejected=%d)", len(opened), maxDirectTCPIPChannelsPerConn, rejected)
	}
	if rejected != burst-maxDirectTCPIPChannelsPerConn {
		t.Fatalf("concurrent burst rejected %d channels with ResourceShortage, want %d", rejected, burst-maxDirectTCPIPChannelsPerConn)
	}
	if got := handoffCalls.Load(); got != maxDirectTCPIPChannelsPerConn {
		t.Fatalf("apiHandoff calls = %d, want %d", got, maxDirectTCPIPChannelsPerConn)
	}
}

// Rejected direct-tcpip channels (such as non-loopback targets) must release
// their channel slot so they cannot permanently exhaust the connection's cap.
func TestRejectedDirectTCPIPChannelReleasesSlot(t *testing.T) {
	srv, tmpDir := testServer(t)
	set := newEnrolledSet()
	srv.SetProductHooks(set.hooks())
	srv.SetAPIHandoff(func(conn *APIConn) error {
		go func() {
			defer func() { _ = conn.Close() }()
			_, _ = io.Copy(io.Discard, conn)
		}()
		return nil
	})

	host, port, known := startServer(t, srv, tmpDir)
	client, _ := connectEnrolledClient(t, srv, set, tmpDir, host, port, known)
	client.mu.Lock()
	sshClient := client.sshClient
	client.mu.Unlock()

	for i := 0; i < maxDirectTCPIPChannelsPerConn+2; i++ {
		if _, err := sshClient.Dial("tcp", net.JoinHostPort("10.0.0.1", "80")); err == nil {
			t.Fatalf("non-loopback dial %d unexpectedly succeeded", i+1)
		}
	}

	for i := 0; i < maxDirectTCPIPChannelsPerConn; i++ {
		c, err := client.DialSignerAPI(context.Background())
		if err != nil {
			t.Fatalf("valid DialSignerAPI(%d) after rejected dials failed: %v", i+1, err)
		}
		t.Cleanup(func() { _ = c.Close() })
	}
}
