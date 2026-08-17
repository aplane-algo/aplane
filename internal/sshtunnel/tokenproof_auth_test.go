// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestClientRejectsServerThatSkipsMutualTokenProof(t *testing.T) {
	srv, tmpDir := testServer(t)
	_, _, identityPath := generateClientIdentityFile(t, tmpDir)

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	serverConfig.AddHostKey(srv.hostKey)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
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
		serverConn, channels, requests, handshakeErr := ssh.NewServerConn(conn, serverConfig)
		if handshakeErr != nil {
			return
		}
		go ssh.DiscardRequests(requests)
		go func() {
			for channel := range channels {
				_ = channel.Reject(ssh.Prohibited, "proof required")
			}
		}()
		_ = serverConn.Wait()
	}()

	host, port := splitHostPort(t, listener.Addr().String())
	knownHostsPath := filepath.Join(tmpDir, "known_hosts")
	line := knownhosts.Line([]string{hostWithPort(host, port)}, srv.hostKey.PublicKey()) + "\n"
	if err := os.WriteFile(knownHostsPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	client := NewClient(host, port, 0, 0, identityPath, knownHostsPath)
	client.SetAPIToken("test-token")
	err = client.ConnectWithKey(context.Background())
	if err == nil || !strings.Contains(err.Error(), "did not complete mutual token proof") {
		t.Fatalf("ConnectWithKey() error = %v, want skipped-proof rejection", err)
	}
	if client.IsConnected() || client.listener != nil {
		t.Fatal("client exposed a usable connection after skipped token proof")
	}

	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not observe rejected connection closing")
	}
}

func TestClientRejectsInvalidServerTokenProof(t *testing.T) {
	srv, tmpDir := testServer(t)
	srv.invalidTokenDelay = 0
	_, clientPub, identityPath := generateClientIdentityFile(t, tmpDir)
	srv.authKeysMu.Lock()
	srv.authKeys = append(srv.authKeys, clientPub)
	srv.authKeysMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Stop() }()

	host, port := splitHostPort(t, srv.listener.Addr().String())
	knownHostsPath := filepath.Join(tmpDir, "known_hosts")
	line := knownhosts.Line([]string{hostWithPort(host, port)}, srv.hostKey.PublicKey()) + "\n"
	if err := os.WriteFile(knownHostsPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	client := NewClient(host, port, 0, 0, identityPath, knownHostsPath)
	client.SetAPIToken("wrong-token")
	if err := client.ConnectWithKey(context.Background()); err == nil {
		t.Fatal("ConnectWithKey() succeeded with a wrong token")
	}
	if client.IsConnected() || client.listener != nil {
		t.Fatal("client exposed a usable connection after invalid server proof")
	}
}

func TestClientRejectsServerProofBoundToAnotherHostKey(t *testing.T) {
	_, observedHostKey := generateClientKey(t)
	_, proofHostKey := generateClientKey(t)
	authState := newTokenProofClientAuth("default", "test-token")
	defer authState.clear()
	if err := authState.captureHostKey(observedHostKey); err != nil {
		t.Fatal(err)
	}

	clientNonceQuestion, err := marshalClientNonceQuestion()
	if err != nil {
		t.Fatal(err)
	}
	answers, err := authState.challenge(tokenProofDomain, "", []string{clientNonceQuestion}, []bool{false})
	if err != nil {
		t.Fatal(err)
	}
	clientNonce, err := parseClientNonceAnswer(answers[0])
	if err != nil {
		t.Fatal(err)
	}
	serverNonce := bytes.Repeat([]byte{0x77}, tokenProofNonceSize)
	proofHostHash, err := hashSSHHostKey(proofHostKey)
	if err != nil {
		t.Fatal(err)
	}
	transcript, err := encodeTokenProofTranscript(tokenProofTranscript{
		Identity:    "default",
		HostKeyHash: proofHostHash,
		ClientNonce: clientNonce,
		ServerNonce: serverNonce,
	})
	if err != nil {
		t.Fatal(err)
	}
	serverProof, err := computeTokenProof("test-token", tokenProofServerDomain, transcript)
	if err != nil {
		t.Fatal(err)
	}
	question, err := marshalServerProofQuestion(serverNonce, serverProof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authState.challenge(tokenProofDomain, "", []string{question}, []bool{false}); err == nil {
		t.Fatal("client accepted a server proof bound to another host key")
	}
	if authState.serverVerified() {
		t.Fatal("client marked a wrong-host server proof as verified")
	}
}

func TestClientUsesProductIdentityBeforeDial(t *testing.T) {
	_, _, identityPath := generateClientIdentityFile(t, t.TempDir())
	client := NewClient("127.0.0.1", 1, 0, 0, identityPath, filepath.Join(t.TempDir(), "known_hosts"))
	client.SetAPIToken("test-token")
	err := client.ConnectWithKey(context.Background())
	if err == nil || strings.Contains(err.Error(), "identity ID required") {
		t.Fatalf("ConnectWithKey() error = %v, want a dial failure after selecting the product identity", err)
	}
}

func TestVerifiedPublicKeyTransitionsOnlyNormalAuthToTokenProof(t *testing.T) {
	srv, _ := testServer(t)
	permissions := &ssh.Permissions{Extensions: map[string]string{
		"auth_method":     "publickey_pending_token_proof",
		"identity_id":     "default",
		"key_fingerprint": "SHA256:test",
	}}
	_, err := srv.handleVerifiedPublicKeyAuth(testConnMetadata{user: "default"}, nil, permissions, "")
	partial, ok := err.(*ssh.PartialSuccessError)
	if !ok || partial.Next.KeyboardInteractiveCallback == nil {
		t.Fatal("verified normal key did not require keyboard-interactive token proof")
	}

	provisioning := &ssh.Permissions{Extensions: map[string]string{"auth_method": "token_provisioning"}}
	got, err := srv.handleVerifiedPublicKeyAuth(testConnMetadata{user: "request-token:default"}, nil, provisioning, "")
	if err != nil || got != provisioning {
		t.Fatalf("verified provisioning key = (%#v, %v), want key-only success", got, err)
	}
}
