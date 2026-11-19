// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestEnrollmentFingerprintMatchesApprovedKey(t *testing.T) {
	for _, mode := range []string{"existing", "generated", "agent"} {
		t.Run(mode, func(t *testing.T) {
			srv, dir := testServer(t)
			approval := make(chan string, 1)
			setEnrollmentHooks(srv, EnrollmentHooks{
				Request: func(key ssh.PublicKey, _, _ string) (bool, error) {
					approval <- ssh.FingerprintSHA256(key)
					return true, nil
				},
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
			client := NewClient(host, port, identity, known)
			var displayed string
			client.SetEnrollmentStartCallback(func(fingerprint string) { displayed = fingerprint })
			result, err := client.RequestEnrollment(ctx, "")
			if err != nil {
				t.Fatalf("RequestEnrollment() error = %v", err)
			}
			if !result.Pending {
				t.Fatalf("RequestEnrollment() = %+v, want a pending request", result)
			}
			select {
			case expected := <-approval:
				if displayed == "" || displayed != expected || result.Fingerprint != expected {
					t.Fatalf("client=%q server=%q requested=%q", displayed, expected, result.Fingerprint)
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

// serveTestAgent serves an SSH agent holding one new Ed25519 key on a socket
// that SSH_AUTH_SOCK names for the test, and returns that key's fingerprint.
func serveTestAgent(t *testing.T) string {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	t.Setenv("SSH_AUTH_SOCK", sock)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = agent.ServeAgent(keyring, conn)
			}()
		}
	}()
	return ssh.FingerprintSHA256(signer.PublicKey())
}

// A configured identity file that is missing and cannot be created is an
// error naming the file and the cause, for connect and enroll alike. The
// client never falls back to the SSH agent's keys, which an enrollment
// request would offer to the operator in place of the configured identity.
func TestIdentityThatCannotBeCreatedIsAnError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write in a read-only directory")
	}
	serveTestAgent(t)
	dir := t.TempDir()
	readOnly := filepath.Join(dir, "read-only")
	if err := os.Mkdir(readOnly, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(readOnly, 0o700) })
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "missing-target"), dangling); err != nil {
		t.Fatal(err)
	}
	unmakeable := filepath.Join(readOnly, "sub", "id_ed25519")
	unwritable := filepath.Join(readOnly, "id_ed25519")
	for name, tc := range map[string]struct{ identity, want string }{
		"directory cannot be made": {unmakeable, "create SSH identity " + unmakeable + ": failed to create directory"},
		"file cannot be written":   {unwritable, "create SSH identity " + unwritable + ": failed to write private key"},
		// A name is in the way of the new file, as when another process
		// created it first, and there is still no key to read there.
		"name in the way": {dangling, "failed to read SSH identity file " + dangling},
	} {
		t.Run(name, func(t *testing.T) {
			client := NewClient("example.com", 22, tc.identity, filepath.Join(dir, "known_hosts"))
			method, conn, err := client.authMethod(nil)
			if conn != nil {
				_ = conn.Close()
			}
			if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("authMethod() = %v, %v; want the error %q, not the agent's keys", method, err, tc.want)
			}
		})
	}

	t.Run("enrollment", func(t *testing.T) {
		srv, srvDir := testServer(t)
		offered := make(chan string, 1)
		setEnrollmentHooks(srv, EnrollmentHooks{
			Request: func(key ssh.PublicKey, _, _ string) (bool, error) {
				offered <- ssh.FingerprintSHA256(key)
				return true, nil
			},
		})
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		if err := srv.Start(ctx); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = srv.Stop() }()
		host, port := splitHostPort(t, srv.listener.Addr().String())
		known := filepath.Join(srvDir, "known_hosts")
		line := knownhosts.Line([]string{hostWithPort(host, port)}, srv.hostKey.PublicKey()) + "\n"
		if err := os.WriteFile(known, []byte(line), 0600); err != nil {
			t.Fatal(err)
		}

		result, err := NewClient(host, port, unwritable, known).RequestEnrollment(ctx, "")
		if err == nil || !strings.Contains(err.Error(), "create SSH identity "+unwritable) {
			t.Fatalf("RequestEnrollment() = %+v, %v; want the identity's creation failure", result, err)
		}
		select {
		case fingerprint := <-offered:
			t.Fatalf("the node was asked to enroll %s, want no request", fingerprint)
		default:
		}
	})
}

// An encrypted identity file is refused with what to change: the endpoint's
// identity_file, since a configured endpoint has no way to use an agent.
func TestEncryptedIdentityFileNamesTheFix(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "", []byte("passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(identity, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = NewClient("example.com", 22, identity, filepath.Join(t.TempDir(), "known_hosts")).authMethod(nil)
	want := "the SSH key at " + identity + " is encrypted, so apshell can't use it; point the endpoint's identity_file at an unencrypted key"
	if err == nil || err.Error() != want {
		t.Fatalf("authMethod() error = %v, want %q", err, want)
	}
}
