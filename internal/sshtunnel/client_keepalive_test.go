// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// TestClientKeepaliveClosesASilentConnection pins that the client notices a
// server that keeps TCP open but stops answering (a partition, a suspended
// VM): a keepalive with no reply within the timeout closes the connection
// and reports the disconnect, rather than waiting for TCP to give up.
func TestClientKeepaliveClosesASilentConnection(t *testing.T) {
	tmpDir := t.TempDir()
	_, clientPub, identityPath := generateClientIdentityFile(t, tmpDir)
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), clientPub.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unknown key")
		},
	}
	config.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, chans, reqs, handshakeErr := ssh.NewServerConn(conn, config)
		if handshakeErr != nil {
			return
		}
		go func() {
			for newChannel := range chans {
				_ = newChannel.Reject(ssh.Prohibited, "no channels")
			}
		}()
		// The server has gone silent: every request is read and none is
		// answered, until the client closes the connection.
		for range reqs {
		}
	}()

	host, port := splitHostPort(t, listener.Addr().String())
	knownHostsPath := filepath.Join(tmpDir, "known_hosts")
	knownHost := knownhosts.Line([]string{hostWithPort(host, port)}, hostSigner.PublicKey()) + "\n"
	if err := os.WriteFile(knownHostsPath, []byte(knownHost), 0o600); err != nil {
		t.Fatal(err)
	}

	client := NewClient(host, port, identityPath, knownHostsPath)
	shortenClientKeepalive(client, 20*time.Millisecond, 100*time.Millisecond)
	disconnected := make(chan struct{})
	var once sync.Once
	client.SetDisconnectCallback(func() { once.Do(func() { close(disconnected) }) })
	if err := client.ConnectWithKey(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	select {
	case <-disconnected:
	case <-time.After(3 * time.Second):
		t.Fatal("the client did not notice a server that stopped answering keepalives")
	}
	if client.IsConnected() {
		t.Fatal("IsConnected() = true after the keepalive timeout")
	}
	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatal("the client did not close the silent connection")
	}
}
