// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"github.com/aplane-algo/aplane/internal/productmode"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"golang.org/x/crypto/ssh"
)

func TestUpdateTokenRevokesActiveConnections(t *testing.T) {
	srv, _ := testServer(t)

	clientSigner, clientPub := generateClientKey(t)
	srv.authKeysMu.Lock()
	srv.authKeys = append(srv.authKeys, clientPub)
	srv.authKeysMu.Unlock()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	serverReady := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			close(serverReady)
			return
		}
		defer func() { _ = conn.Close() }()

		sshServerConn, chans, globalReqs, sshErr := ssh.NewServerConn(conn, srv.sshConfig)
		if sshErr != nil {
			close(serverReady)
			return
		}
		defer func() { _ = sshServerConn.Close() }()
		go ssh.DiscardRequests(globalReqs)
		go func() {
			for newChannel := range chans {
				_ = newChannel.Reject(ssh.Prohibited, "no channels in test")
			}
		}()

		srv.sshConnsMu.Lock()
		srv.sshConns[sshServerConn] = sshConnInfo{}
		srv.sshConnsMu.Unlock()
		close(serverReady) // Signal that connection is registered
		defer func() {
			srv.sshConnsMu.Lock()
			delete(srv.sshConns, sshServerConn)
			srv.sshConnsMu.Unlock()
		}()

		<-srv.closeChan
	}()

	clientConfig := tokenProofTestClientConfig(t, srv, clientSigner, "default", "test-token")
	clientConfig.Timeout = 5 * time.Second

	clientConn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	cc, _, reqs, err := ssh.NewClientConn(clientConn, ln.Addr().String(), clientConfig)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer func() { _ = cc.Close() }()

	// Wait for the server goroutine to register the connection
	select {
	case <-serverReady:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server to register connection")
	}

	if got := srv.ActiveConnectionCount(); got != 1 {
		t.Fatalf("ActiveConnectionCount() = %d, want 1", got)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.UpdateToken("new-token")
		close(srv.closeChan)
	}()

	select {
	case req := <-reqs:
		switch {
		case req == nil:
			t.Fatal("expected token revocation request, got nil")
		case req.Type != "token-revoked@aplane":
			t.Fatalf("global request type = %q, want %q", req.Type, "token-revoked@aplane")
		case req.WantReply:
			t.Fatal("token revocation request should not require reply")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for token revocation request")
	}

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- cc.Wait()
	}()

	select {
	case err := <-waitDone:
		if err == nil {
			t.Fatal("expected client connection to close after token revocation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for connection close after token revocation")
	}

	<-done
	<-serverDone
}

func TestCloseProductConnectionsRevokesEveryConnection(t *testing.T) {
	srv, _ := testServer(t)

	first := newActiveSSHTestConn(t, srv)
	defer first.close()
	second := newActiveSSHTestConn(t, srv)
	defer second.close()

	srv.CloseProductConnections(0, "token revoked")

	select {
	case req := <-first.reqs:
		switch {
		case req == nil:
			t.Fatal("expected first token revocation request, got nil")
		case req.Type != "token-revoked@aplane":
			t.Fatalf("first global request type = %q, want token-revoked@aplane", req.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first token revocation request")
	}

	select {
	case req := <-second.reqs:
		switch {
		case req == nil:
			t.Fatal("expected second token revocation request, got nil")
		case req.Type != "token-revoked@aplane":
			t.Fatalf("second global request type = %q, want token-revoked@aplane", req.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for second token revocation request")
	}

	firstWait := make(chan error, 1)
	go func() {
		firstWait <- first.clientConn.Wait()
	}()
	select {
	case err := <-firstWait:
		if err == nil {
			t.Fatal("expected first connection to close after product revocation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first connection close")
	}

	secondWait := make(chan error, 1)
	go func() {
		secondWait <- second.clientConn.Wait()
	}()
	select {
	case err := <-secondWait:
		if err == nil {
			t.Fatal("expected second connection to close after product revocation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for second connection close")
	}
}

func TestTokenRotationDuringSSHAuthClosesOldGenerationAfterTrack(t *testing.T) {
	srv, _ := testServer(t)
	tokenAuth := auth.NewTokenAuthenticator("old-token")
	srv.SetProductHooks(ProductHooks{
		ComputeTokenMACs: func(serverInput, clientInput []byte) ([]byte, []byte, uint64, bool) {
			return tokenAuth.ComputeHMACPair(serverInput, clientInput)
		},
		CheckKey: func(key ssh.PublicKey) bool {
			return true
		},
		EnrollKey: func(key ssh.PublicKey) error { return nil },
	})

	authComplete := make(chan struct{})
	releaseTrack := make(chan struct{})
	var authOnce sync.Once
	var releaseOnce sync.Once
	srv.testAfterAuthBeforeTrack = func() {
		authOnce.Do(func() { close(authComplete) })
		<-releaseTrack
	}
	defer releaseOnce.Do(func() { close(releaseTrack) })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		srv.activeConns.Add(1)
		srv.handleConnection(conn)
	}()

	clientSigner, _ := generateClientKey(t)
	clientConfig := tokenProofTestClientConfig(t, srv, clientSigner, productmode.IdentityID, "old-token")
	clientConfig.Timeout = 5 * time.Second

	clientNetConn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = clientNetConn.Close() }()

	cc, _, reqs, err := ssh.NewClientConn(clientNetConn, ln.Addr().String(), clientConfig)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer func() { _ = cc.Close() }()

	select {
	case <-authComplete:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for SSH auth to reach pre-track hook")
	}
	if got := srv.ActiveConnectionCount(); got != 0 {
		t.Fatalf("ActiveConnectionCount before tracking = %d, want 0", got)
	}

	tokenAuth.UpdateToken("new-token")
	srv.CloseProductConnections(tokenAuth.Generation(), "token revoked")
	releaseOnce.Do(func() { close(releaseTrack) })

	select {
	case req := <-reqs:
		switch {
		case req == nil:
			t.Fatal("expected token revocation request, got nil")
		case req.Type != "token-revoked@aplane":
			t.Fatalf("global request type = %q, want token-revoked@aplane", req.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for stale auth revocation request")
	}

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- cc.Wait()
	}()
	select {
	case err := <-waitDone:
		if err == nil {
			t.Fatal("expected client connection to close after stale auth was tracked")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for stale auth connection close")
	}

	<-serverDone
}

type activeSSHTestConn struct {
	clientConn ssh.Conn
	reqs       <-chan *ssh.Request
	close      func()
}

func newActiveSSHTestConn(t *testing.T, srv *Server) activeSSHTestConn {
	t.Helper()

	clientSigner, clientPub := generateClientKey(t)
	srv.authKeysMu.Lock()
	srv.authKeys = append(srv.authKeys, clientPub)
	srv.authKeysMu.Unlock()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	serverReady := make(chan struct{})
	serverDone := make(chan struct{})
	releaseServer := make(chan struct{})
	var serverConn *ssh.ServerConn
	go func() {
		defer close(serverDone)
		defer func() { _ = ln.Close() }()
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			close(serverReady)
			return
		}
		defer func() { _ = conn.Close() }()

		sshServerConn, chans, globalReqs, sshErr := ssh.NewServerConn(conn, srv.sshConfig)
		if sshErr != nil {
			close(serverReady)
			return
		}
		serverConn = sshServerConn
		defer func() { _ = sshServerConn.Close() }()
		go ssh.DiscardRequests(globalReqs)
		go func() {
			for newChannel := range chans {
				_ = newChannel.Reject(ssh.Prohibited, "no channels in test")
			}
		}()

		srv.sshConnsMu.Lock()
		srv.sshConns[sshServerConn] = sshConnInfo{}
		srv.sshConnsMu.Unlock()
		close(serverReady)
		defer func() {
			srv.sshConnsMu.Lock()
			delete(srv.sshConns, sshServerConn)
			srv.sshConnsMu.Unlock()
		}()

		<-releaseServer
	}()

	clientConfig := tokenProofTestClientConfig(t, srv, clientSigner, productmode.IdentityID, "test-token")
	clientConfig.Timeout = 5 * time.Second

	clientNetConn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	cc, _, reqs, err := ssh.NewClientConn(clientNetConn, ln.Addr().String(), clientConfig)
	if err != nil {
		_ = clientNetConn.Close()
		t.Fatalf("client connect: %v", err)
	}

	select {
	case <-serverReady:
	case <-time.After(5 * time.Second):
		_ = cc.Close()
		_ = clientNetConn.Close()
		t.Fatal("timed out waiting for server to register connection")
	}
	if serverConn == nil {
		_ = cc.Close()
		_ = clientNetConn.Close()
		t.Fatal("server connection was not established")
	}

	closed := make(chan struct{})
	closeFn := func() {
		select {
		case <-closed:
			return
		default:
			close(closed)
		}
		close(releaseServer)
		_ = cc.Close()
		_ = clientNetConn.Close()
		_ = serverConn.Close()
	}

	return activeSSHTestConn{
		clientConn: cc,
		reqs:       reqs,
		close: func() {
			closeFn()
			<-serverDone
		},
	}
}
