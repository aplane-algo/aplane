// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func mustSSHPublicKey(t *testing.T, key any) ssh.PublicKey {
	t.Helper()
	pub, err := ssh.NewPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// typedKey is a public key that reports only its type, for key types the
// standard library no longer generates.
type typedKey string

func (k typedKey) Type() string                        { return string(k) }
func (k typedKey) Marshal() []byte                     { return nil }
func (k typedKey) Verify([]byte, *ssh.Signature) error { return nil }

func TestCheckEnrollmentKey(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey := func(bits int) *rsa.PublicKey {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		return &k.PublicKey
	}
	for _, tc := range []struct {
		name   string
		key    any
		accept bool
	}{
		{"ed25519", edPub, true},
		{"ecdsa-p256", &ecKey.PublicKey, true},
		{"rsa-3072", rsaKey(3072), false},
		{"dsa", typedKey("ssh-dss"), false},
		{"certificate", typedKey(ssh.CertAlgoED25519v01), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub, ok := tc.key.(ssh.PublicKey)
			if !ok {
				pub = mustSSHPublicKey(t, tc.key)
			}
			err := checkEnrollmentKey(pub)
			if (err == nil) != tc.accept {
				t.Fatalf("checkEnrollmentKey() error = %v, want accept=%v", err, tc.accept)
			}
		})
	}
}

// An RSA key is refused by the algorithm allowlist, before the server parses
// it, consults PublicKeyCallback, or verifies a signature. The allowlist check
// precedes the query/signed split in the SSH library, so this also covers a
// client that sends a signed request without a preliminary query, which the
// Go client cannot be made to do.
func TestRSAClientKeyRefusedBeforeVerification(t *testing.T) {
	srv, _ := testServer(t)
	prompted := false
	consulted := false
	callback := srv.sshConfig.PublicKeyCallback
	srv.sshConfig.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		consulted = true
		return callback(conn, key)
	}
	setTokenProvisioningHooks(srv, TokenProvisioningHooks{
		ApproveContext: func(context.Context, string, string) (bool, error) { prompted = true; return false, nil },
		Issue:          func() (string, error) { return "", nil },
	})
	weak, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(weak)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ssh.Dial("tcp", serveConnections(t, srv), &ssh.ClientConfig{
		User:            tokenRequestSSHUsername,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(srv.hostKey.PublicKey()),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Fatal("request-token accepted an RSA key")
	}
	if consulted || prompted {
		t.Fatalf("RSA key got past the algorithm allowlist (callback=%v, prompt=%v)", consulted, prompted)
	}
}
