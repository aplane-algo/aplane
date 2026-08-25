// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestServerCallbackSettersBeforeStart(t *testing.T) {
	srv, _ := testServer(t)

	srv.SetSessionCallback(func(remoteAddr string, connected bool) {})
	srv.SetTokenProvisioningHooks(TokenProvisioningHooks{
		Approve:           func(sshFingerprint, remoteAddr string) (bool, error) { return true, nil },
		Issue:             func() (string, error) { return "token", nil },
		AuditProvisioned:  func(sshFingerprint, remoteAddr string) {},
		OperatorConnected: func() bool { return true },
	})
	srv.SetProductHooks(ProductHooks{
		ComputeTokenMACs: testTokenMACs,
		CheckKey:         func(key ssh.PublicKey) bool { return true },
		EnrollKey:        func(key ssh.PublicKey) error { return nil },
	})
	srv.SetAdminChannelCallback(func(channel ssh.Channel, remoteAddr string) {})

	if srv.sessionCallback == nil ||
		srv.tokenApprovalCallback == nil ||
		srv.tokenIssuanceCallback == nil ||
		srv.tokenAuditCallback == nil ||
		srv.operatorCheckCallback == nil ||
		srv.tokenMAC == nil ||
		srv.keyChecker == nil ||
		srv.keyEnroller == nil ||
		srv.adminChannelCallback == nil {
		t.Fatal("expected all callback setters to apply before Start")
	}
}

func TestServerStopContextReportsActiveHandlerTimeout(t *testing.T) {
	srv, _ := testServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Model a handler that remains alive after the listener/accept loop exits.
	srv.activeConns.Add(1)
	defer srv.activeConns.Done()
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stopCancel()
	if err := srv.StopContext(stopCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("StopContext() error = %v, want context deadline exceeded", err)
	}
}

func TestSSHAuthLogOmitsUsernameAndErrorDetails(t *testing.T) {
	const secret = "reusable-token-shaped-secret"
	line := formatSSHAuthLog(testConnMetadata{user: secret}, "keyboard-interactive", fmt.Errorf("bad proof for %s", secret))
	if strings.Contains(line, secret) {
		t.Fatalf("auth log contains SSH username or error details: %q", line)
	}
	if !strings.Contains(line, "method=keyboard-interactive") || !strings.Contains(line, "outcome=rejected") {
		t.Fatalf("auth log omits method or outcome: %q", line)
	}
}

func TestSetProductHooksRejectsPartialConfiguration(t *testing.T) {
	tests := []struct {
		name  string
		hooks ProductHooks
	}{
		{
			name: "token MAC only",
			hooks: ProductHooks{
				ComputeTokenMACs: testTokenMACs,
			},
		},
		{
			name: "missing enroller",
			hooks: ProductHooks{
				ComputeTokenMACs: testTokenMACs,
				CheckKey:         func(key ssh.PublicKey) bool { return true },
			},
		},
		{
			name: "enroller only",
			hooks: ProductHooks{
				EnrollKey: func(key ssh.PublicKey) error { return nil },
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _ := testServer(t)
			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("SetProductHooks did not panic for partial hooks")
				}
				msg, ok := r.(string)
				if !ok || !strings.Contains(msg, "require ComputeTokenMACs, CheckKey, and EnrollKey together") {
					t.Fatalf("panic = %#v, want partial identity hook assertion", r)
				}
			}()
			srv.SetProductHooks(tt.hooks)
		})
	}
}

func TestProductAuthRejectsPartialHooksWithoutGlobalKeyFallback(t *testing.T) {
	srv, _ := testServer(t)
	_, pub := generateClientKey(t)
	srv.authKeysMu.Lock()
	srv.authKeys = append(srv.authKeys, pub)
	srv.authKeysMu.Unlock()
	srv.tokenMAC = testTokenMACs

	perms, err := srv.handlePublicKeyAuth(testConnMetadata{user: productSSHUsername}, pub)
	if perms != nil {
		t.Fatalf("handlePublicKeyAuth() permissions = %#v, want nil", perms)
	}
	if err == nil || !strings.Contains(err.Error(), "not fully configured") {
		t.Fatalf("handlePublicKeyAuth() error = %v, want partial identity hook rejection", err)
	}
}

func TestProductAuthChecksKeyAfterFixedUsernameValidation(t *testing.T) {
	srv, _ := testServer(t)
	_, pub := generateClientKey(t)
	srv.tokenMAC = testTokenMACs
	checked := false
	srv.keyChecker = func(key ssh.PublicKey) bool {
		checked = true
		return true
	}
	srv.keyEnroller = func(key ssh.PublicKey) error { return nil }

	perms, err := srv.handlePublicKeyAuth(testConnMetadata{user: productSSHUsername}, pub)
	if err != nil {
		t.Fatalf("handlePublicKeyAuth() error = %v", err)
	}
	if !checked || perms.Extensions["auth_method"] != "publickey_pending_token_proof" {
		t.Fatalf("product binding = checked %v permissions %#v", checked, perms)
	}
}

func TestProductAuthRejectsNonProductUsernameBeforeKeyCheck(t *testing.T) {
	srv, _ := testServer(t)
	_, pub := generateClientKey(t)
	srv.tokenMAC = testTokenMACs
	checked := false
	srv.keyChecker = func(key ssh.PublicKey) bool {
		checked = true
		return true
	}
	srv.keyEnroller = func(key ssh.PublicKey) error { return nil }

	for _, username := range []string{"other-identity", "request-token:other-identity"} {
		t.Run(username, func(t *testing.T) {
			checked = false
			perms, err := srv.handlePublicKeyAuth(testConnMetadata{user: username}, pub)
			if perms != nil {
				t.Fatalf("handlePublicKeyAuth() permissions = %#v, want nil", perms)
			}
			if err == nil || !strings.Contains(err.Error(), "unsupported SSH username") {
				t.Fatalf("handlePublicKeyAuth() error = %v, want unsupported username", err)
			}
			if checked {
				t.Fatal("non-product username reached product key check")
			}
		})
	}
}

func TestNextAcceptErrorBackoff(t *testing.T) {
	tests := []struct {
		name    string
		current time.Duration
		want    time.Duration
	}{
		{
			name:    "initial",
			current: 0,
			want:    initialAcceptErrorBackoff,
		},
		{
			name:    "doubles",
			current: initialAcceptErrorBackoff,
			want:    2 * initialAcceptErrorBackoff,
		},
		{
			name:    "caps",
			current: maxAcceptErrorBackoff,
			want:    maxAcceptErrorBackoff,
		},
		{
			name:    "caps after overflow past max",
			current: maxAcceptErrorBackoff / 2 * 3,
			want:    maxAcceptErrorBackoff,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nextAcceptErrorBackoff(tt.current); got != tt.want {
				t.Fatalf("nextAcceptErrorBackoff(%s) = %s, want %s", tt.current, got, tt.want)
			}
		})
	}
}

func TestServerCallbackSettersPanicAfterStart(t *testing.T) {
	srv, _ := testServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() { _ = srv.Stop() }()

	tests := []struct {
		name string
		call func()
	}{
		{
			name: "SetSessionCallback",
			call: func() { srv.SetSessionCallback(func(remoteAddr string, connected bool) {}) },
		},
		{
			name: "SetTokenProvisioningHooks",
			call: func() {
				srv.SetTokenProvisioningHooks(TokenProvisioningHooks{
					Approve:           func(sshFingerprint, remoteAddr string) (bool, error) { return true, nil },
					Issue:             func() (string, error) { return "token", nil },
					AuditProvisioned:  func(sshFingerprint, remoteAddr string) {},
					OperatorConnected: func() bool { return true },
				})
			},
		},
		{
			name: "SetProductHooks",
			call: func() {
				srv.SetProductHooks(ProductHooks{
					ComputeTokenMACs: testTokenMACs,
					CheckKey:         func(key ssh.PublicKey) bool { return true },
					EnrollKey:        func(key ssh.PublicKey) error { return nil },
				})
			},
		},
		{
			name: "SetAdminChannelCallback",
			call: func() { srv.SetAdminChannelCallback(func(channel ssh.Channel, remoteAddr string) {}) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("setter did not panic after Start")
				}
				msg, ok := r.(string)
				if !ok || !strings.Contains(msg, tt.name) || !strings.Contains(msg, "cannot be called after Start") {
					t.Fatalf("panic = %#v, want %s after-Start assertion", r, tt.name)
				}
			}()
			tt.call()
		})
	}
}

type testConnMetadata struct {
	user string
}

func testTokenMACs(serverInput, clientInput []byte) ([]byte, []byte, uint64, bool) {
	return make([]byte, tokenProofMACSize), make([]byte, tokenProofMACSize), 1, true
}

func (m testConnMetadata) User() string {
	return m.user
}

func (m testConnMetadata) SessionID() []byte {
	return nil
}

func (m testConnMetadata) ClientVersion() []byte {
	return []byte("SSH-2.0-test-client")
}

func (m testConnMetadata) ServerVersion() []byte {
	return []byte("SSH-2.0-test-server")
}

func (m testConnMetadata) RemoteAddr() net.Addr {
	return testNetAddr("127.0.0.1:12345")
}

func (m testConnMetadata) LocalAddr() net.Addr {
	return testNetAddr("127.0.0.1:22")
}

type testNetAddr string

func (a testNetAddr) Network() string {
	return "tcp"
}

func (a testNetAddr) String() string {
	return string(a)
}
