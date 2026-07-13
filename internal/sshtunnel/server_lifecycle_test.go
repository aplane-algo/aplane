// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestServerCallbackSettersBeforeStart(t *testing.T) {
	srv, _ := testServer(t)

	srv.SetSessionCallback(func(remoteAddr, user string, connected bool) {})
	srv.SetTokenProvisioningHooks(TokenProvisioningHooks{
		Approve:              func(identityID, sshFingerprint, remoteAddr string) (bool, error) { return true, nil },
		Issue:                func(identityID string) (string, error) { return "token", nil },
		AuditProvisioned:     func(identityID, sshFingerprint, remoteAddr string) {},
		OperatorConnected:    func(identityID string) bool { return true },
		IdentityProvisioning: func(identityID string) bool { return true },
	})
	srv.SetIdentityHooks(IdentityHooks{
		ComputeTokenMACs: testTokenMACs,
		CheckKey:         func(identityID string, key ssh.PublicKey) bool { return true },
		EnrollKey:        func(identityID string, key ssh.PublicKey) error { return nil },
	})
	srv.SetAdminChannelCallback(func(channel ssh.Channel, remoteAddr, identityID string) {})

	if srv.sessionCallback == nil ||
		srv.tokenApprovalCallback == nil ||
		srv.tokenIssuanceCallback == nil ||
		srv.tokenAuditCallback == nil ||
		srv.operatorCheckCallback == nil ||
		srv.provisioningIdentityCheck == nil ||
		srv.tokenMAC == nil ||
		srv.keyChecker == nil ||
		srv.keyEnroller == nil ||
		srv.adminChannelCallback == nil {
		t.Fatal("expected all callback setters to apply before Start")
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

func TestSetIdentityHooksRejectsPartialConfiguration(t *testing.T) {
	tests := []struct {
		name  string
		hooks IdentityHooks
	}{
		{
			name: "token MAC only",
			hooks: IdentityHooks{
				ComputeTokenMACs: testTokenMACs,
			},
		},
		{
			name: "missing enroller",
			hooks: IdentityHooks{
				ComputeTokenMACs: testTokenMACs,
				CheckKey:         func(identityID string, key ssh.PublicKey) bool { return true },
			},
		},
		{
			name: "enroller only",
			hooks: IdentityHooks{
				EnrollKey: func(identityID string, key ssh.PublicKey) error { return nil },
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _ := testServer(t)
			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("SetIdentityHooks did not panic for partial hooks")
				}
				msg, ok := r.(string)
				if !ok || !strings.Contains(msg, "require ComputeTokenMACs, CheckKey, and EnrollKey together") {
					t.Fatalf("panic = %#v, want partial identity hook assertion", r)
				}
			}()
			srv.SetIdentityHooks(tt.hooks)
		})
	}
}

func TestIdentityAwareAuthRejectsPartialHooksWithoutGlobalKeyFallback(t *testing.T) {
	srv, _ := testServer(t)
	_, pub := generateClientKey(t)
	srv.authKeysMu.Lock()
	srv.authKeys = append(srv.authKeys, pub)
	srv.authKeysMu.Unlock()
	srv.tokenMAC = testTokenMACs

	perms, err := srv.handlePublicKeyAuth(testConnMetadata{user: "alice"}, pub)
	if perms != nil {
		t.Fatalf("handlePublicKeyAuth() permissions = %#v, want nil", perms)
	}
	if err == nil || !strings.Contains(err.Error(), "not fully configured") {
		t.Fatalf("handlePublicKeyAuth() error = %v, want partial identity hook rejection", err)
	}
}

func TestIdentityAwareAuthBindsUsernameIdentityToKeyCheck(t *testing.T) {
	srv, _ := testServer(t)
	_, pub := generateClientKey(t)
	srv.tokenMAC = testTokenMACs
	var checkedIdentity string
	srv.keyChecker = func(identityID string, key ssh.PublicKey) bool {
		checkedIdentity = identityID
		return true
	}
	srv.keyEnroller = func(identityID string, key ssh.PublicKey) error { return nil }

	perms, err := srv.handlePublicKeyAuth(testConnMetadata{user: "alice"}, pub)
	if err != nil {
		t.Fatalf("handlePublicKeyAuth() error = %v", err)
	}
	if checkedIdentity != "alice" || perms.Extensions["identity_id"] != "alice" {
		t.Fatalf("identity binding = checked %q permissions %#v, want alice", checkedIdentity, perms)
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
			call: func() { srv.SetSessionCallback(func(remoteAddr, user string, connected bool) {}) },
		},
		{
			name: "SetTokenProvisioningHooks",
			call: func() {
				srv.SetTokenProvisioningHooks(TokenProvisioningHooks{
					Approve:              func(identityID, sshFingerprint, remoteAddr string) (bool, error) { return true, nil },
					Issue:                func(identityID string) (string, error) { return "token", nil },
					AuditProvisioned:     func(identityID, sshFingerprint, remoteAddr string) {},
					OperatorConnected:    func(identityID string) bool { return true },
					IdentityProvisioning: func(identityID string) bool { return true },
				})
			},
		},
		{
			name: "SetIdentityHooks",
			call: func() {
				srv.SetIdentityHooks(IdentityHooks{
					ComputeTokenMACs: testTokenMACs,
					CheckKey:         func(identityID string, key ssh.PublicKey) bool { return true },
					EnrollKey:        func(identityID string, key ssh.PublicKey) error { return nil },
				})
			},
		},
		{
			name: "SetAdminChannelCallback",
			call: func() { srv.SetAdminChannelCallback(func(channel ssh.Channel, remoteAddr, identityID string) {}) },
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

func testTokenMACs(identityID string, serverInput, clientInput []byte) ([]byte, []byte, uint64, bool) {
	return make([]byte, tokenProofMACSize), make([]byte, tokenProofMACSize), 1, identityID != ""
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
