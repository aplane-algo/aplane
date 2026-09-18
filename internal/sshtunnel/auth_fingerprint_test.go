// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestProvisioningFingerprintMatchesApprovedKey(t *testing.T) {
	for _, mode := range []string{"existing", "generated", "agent"} {
		t.Run(mode, func(t *testing.T) {
			srv, dir := testServer(t)
			approval := make(chan string, 1)
			setTokenProvisioningHooks(srv, TokenProvisioningHooks{
				Approve: func(fingerprint, _ string) (bool, error) { approval <- fingerprint; return true, nil },
				Issue:   func() (string, error) { return "issued-token", nil },
			})
			identity := filepath.Join(dir, "new_identity")
			if mode == "existing" {
				_, _, identity = generateClientIdentityFile(t, dir)
			}
			if mode == "agent" {
				identity = ""
				keyring := agent.NewKeyring()
				_, first, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				_, second, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				for _, key := range []ed25519.PrivateKey{first, second} {
					if err := keyring.Add(agent.AddedKey{PrivateKey: key}); err != nil {
						t.Fatal(err)
					}
				}
				// Force selection of the second agent identity.
				signer, err := ssh.NewSignerFromKey(second)
				if err != nil {
					t.Fatal(err)
				}
				expected := ssh.FingerprintSHA256(signer.PublicKey())
				original := srv.sshConfig.PublicKeyCallback
				srv.sshConfig.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
					if ssh.FingerprintSHA256(key) != expected {
						return nil, fmt.Errorf("test rejects first agent key")
					}
					return original(conn, key)
				}
				sock := filepath.Join(t.TempDir(), "agent.sock")
				listener, err := net.Listen("unix", sock)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = listener.Close() }()
				t.Setenv("SSH_AUTH_SOCK", sock)
				done := make(chan struct{})
				go func() {
					defer close(done)
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					defer func() { _ = conn.Close() }()
					_ = agent.ServeAgent(keyring, conn)
				}()
				defer func() {
					_ = listener.Close()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("agent connection leaked")
					}
				}()
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if err := srv.Start(ctx); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = srv.Stop() }()
			host, port := splitHostPort(t, srv.listener.Addr().String())
			known := filepath.Join(dir, "known_hosts")
			line := knownhosts.Line([]string{hostWithPort(host, port)}, srv.hostKey.PublicKey()) + "\n"
			if err := os.WriteFile(known, []byte(line), 0600); err != nil {
				t.Fatal(err)
			}
			client := NewClient(host, port, 0, 0, identity, known)
			var displayed string
			client.SetProvisioningStartCallback(func(fingerprint string) { displayed = fingerprint })
			token, err := client.RequestToken(ctx)
			if err != nil || token != "issued-token" {
				t.Fatalf("request=%q %v", token, err)
			}
			select {
			case expected := <-approval:
				if displayed == "" || displayed != expected {
					t.Fatalf("client=%q server=%q", displayed, expected)
				}
			default:
				t.Fatal("approval missing")
			}
		})
	}
}

func TestObservedSignerPreservesAlgorithmRestrictions(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	restricted, err := ssh.NewSignerWithAlgorithms(signer.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSASHA512})
	if err != nil {
		t.Fatal(err)
	}
	var observed string
	wrapped := observeAuthSigner(restricted, func(fingerprint string) { observed = fingerprint })
	multi, ok := wrapped.(ssh.MultiAlgorithmSigner)
	if !ok || !reflect.DeepEqual(multi.Algorithms(), restricted.Algorithms()) {
		t.Fatal("changed algorithm restrictions")
	}
	payload := []byte("test SSH authentication payload")
	signature, err := multi.SignWithAlgorithm(rand.Reader, payload, ssh.KeyAlgoRSASHA512)
	if err != nil {
		t.Fatal(err)
	}
	if err := restricted.PublicKey().Verify(payload, signature); err != nil {
		t.Fatal(err)
	}
	if observed != ssh.FingerprintSHA256(restricted.PublicKey()) {
		t.Fatal("wrong observed key")
	}
}
