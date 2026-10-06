// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// connectProductClient starts srv and connects a client that passes key and
// token-proof authentication.
func connectProductClient(t *testing.T, srv *Server, tmpDir string) *Client {
	t.Helper()
	_, clientPub, identityPath := generateClientIdentityFile(t, tmpDir)
	srv.authKeysMu.Lock()
	srv.authKeys = append(srv.authKeys, clientPub)
	srv.authKeysMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	host, port := splitHostPort(t, srv.listener.Addr().String())
	knownHostsPath := filepath.Join(tmpDir, "known_hosts")
	if err := os.WriteFile(knownHostsPath, []byte(knownhosts.Line([]string{hostWithPort(host, port)}, srv.hostKey.PublicKey())+"\n"), 0600); err != nil {
		t.Fatalf("WriteFile(known_hosts) error = %v", err)
	}
	client := NewClient(host, port, 0, identityPath, knownHostsPath)
	client.SetAPIToken("test-token")
	if err := client.ConnectWithKey(context.Background()); err != nil {
		t.Fatalf("ConnectWithKey() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// An authenticated product connection may only forward to the signer API.
// Session channels, which once carried the remote admin subsystem, are
// refused, so the admin protocol is reachable only over local IPC.
func TestProductConnectionRefusesSessionChannels(t *testing.T) {
	srv, tmpDir := testServer(t)
	client := connectProductClient(t, srv, tmpDir)

	client.mu.Lock()
	sshClient := client.sshClient
	client.mu.Unlock()
	_, _, err := sshClient.OpenChannel("session", nil)
	var openErr *ssh.OpenChannelError
	if !errors.As(err, &openErr) || openErr.Reason != ssh.UnknownChannelType {
		t.Fatalf("OpenChannel(session) error = %v, want an unknown-channel-type rejection", err)
	}
}

// A client that keeps its connection open but never answers keepalives is
// closed once the reply timeout passes, instead of the monitor waiting for
// the reply forever.
func TestUnansweredKeepaliveClosesConnection(t *testing.T) {
	srv, _ := testServer(t)
	srv.keepaliveInterval = 20 * time.Millisecond
	srv.keepaliveTimeout = 50 * time.Millisecond
	srv.tokenProvisioningExecDeadline = time.Minute // only the keepalive may close it
	setTokenProvisioningHooks(srv, TokenProvisioningHooks{
		ApproveContext: func(context.Context, string, string) (bool, error) { return false, nil },
		Issue:          func() (string, error) { return "", nil },
	})
	addr := serveConnections(t, srv)

	signer, _ := generateClientKey(t)
	netConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, chans, reqs, err := ssh.NewClientConn(netConn, addr, &ssh.ClientConfig{
		User:            tokenRequestSSHUsername,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(srv.hostKey.PublicKey()),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	go func() {
		for range reqs { // read keepalives, never reply
		}
	}()
	go func() {
		for ch := range chans {
			_ = ch.Reject(ssh.Prohibited, "test")
		}
	}()

	closed := make(chan struct{})
	go func() { _ = conn.Wait(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("connection that never answers keepalives stayed open")
	}
}
