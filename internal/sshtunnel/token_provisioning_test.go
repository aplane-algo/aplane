// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestParseExecCommandRejectsOversizedLength(t *testing.T) {
	if command, ok := parseExecCommand([]byte{0xff, 0xff, 0xff, 0xff}); ok {
		t.Fatalf("parseExecCommand() = (%q, true), want rejection", command)
	}
	if command, ok := parseExecCommand([]byte{0, 0, 0, 9, 'p'}); ok {
		t.Fatalf("parseExecCommand(short payload) = (%q, true), want rejection", command)
	}
	command, ok := parseExecCommand([]byte{0, 0, 0, 9, 'p', 'r', 'o', 'v', 'i', 's', 'i', 'o', 'n'})
	if !ok || command != "provision" {
		t.Fatalf("parseExecCommand(valid) = (%q, %v), want provision true", command, ok)
	}
}

func TestProvisioningPublicKeyStringHandlesNilPermissions(t *testing.T) {
	if got := provisioningPublicKeyString(nil); got != "" {
		t.Fatalf("provisioningPublicKeyString(nil) = %q, want empty", got)
	}
	if got := provisioningPublicKeyString(&ssh.Permissions{}); got != "" {
		t.Fatalf("provisioningPublicKeyString(empty extensions) = %q, want empty", got)
	}
	if got := provisioningPublicKeyString(&ssh.Permissions{Extensions: map[string]string{"public_key": "key"}}); got != "key" {
		t.Fatalf("provisioningPublicKeyString() = %q, want key", got)
	}
}

// testServer creates a minimal Server configured for token provisioning tests.
func testServer(t *testing.T) (*Server, string) {
	t.Helper()
	tmpDir := t.TempDir()

	hostKeyPath := filepath.Join(tmpDir, "host_key")
	authKeysPath := filepath.Join(tmpDir, "authorized_keys")

	srv, err := NewServer("127.0.0.1:0", "127.0.0.1:0", hostKeyPath, authKeysPath, "test-token")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	return srv, tmpDir
}

func setTokenProvisioningHooks(srv *Server, hooks TokenProvisioningHooks) {
	if hooks.OperatorConnected == nil {
		hooks.OperatorConnected = func(identityID string) bool { return true }
	}
	srv.SetTokenProvisioningHooks(hooks)
}

// generateClientKey creates an ephemeral Ed25519 SSH key pair for testing.
func generateClientKey(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return signer, signer.PublicKey()
}

// runProvisioningSession starts a TCP listener, accepts one connection on the
// server side, and connects with an SSH client to run "provision".
func runProvisioningSession(t *testing.T, srv *Server, clientSigner ssh.Signer) (output string, exitCode int, err error) {
	t.Helper()
	return runProvisioningSessionForIdentity(t, srv, clientSigner, "default")
}

func runProvisioningSessionForIdentity(t *testing.T, srv *Server, clientSigner ssh.Signer, identityID string) (output string, exitCode int, err error) {
	t.Helper()

	// Listen on a random port
	ln, listenErr := net.Listen("tcp", "127.0.0.1:0")
	if listenErr != nil {
		return "", -1, fmt.Errorf("listen: %w", listenErr)
	}
	defer func() { _ = ln.Close() }()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		sshServerConn, chans, globalReqs, sshErr := ssh.NewServerConn(conn, srv.sshConfig)
		if sshErr != nil {
			return
		}
		defer func() { _ = sshServerConn.Close() }()
		go ssh.DiscardRequests(globalReqs)

		for newChannel := range chans {
			srv.handleTokenProvisioningChannel(context.Background(), sshServerConn, newChannel)
		}
	}()

	// Client side
	clientConfig := &ssh.ClientConfig{
		User: "request-token:" + identityID,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(clientSigner),
		},
		HostKeyCallback: ssh.FixedHostKey(srv.hostKey.PublicKey()),
		Timeout:         5 * time.Second,
	}

	clientConn, dialErr := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if dialErr != nil {
		return "", -1, fmt.Errorf("dial: %w", dialErr)
	}
	defer func() { _ = clientConn.Close() }()

	cc, chans, reqs, connErr := ssh.NewClientConn(clientConn, ln.Addr().String(), clientConfig)
	if connErr != nil {
		<-serverDone
		return "", -1, fmt.Errorf("client connect: %w", connErr)
	}
	client := ssh.NewClient(cc, chans, reqs)
	defer func() {
		_ = client.Close()
		<-serverDone
	}()

	session, sessErr := client.NewSession()
	if sessErr != nil {
		return "", -1, fmt.Errorf("new session: %w", sessErr)
	}
	defer func() { _ = session.Close() }()

	out, runErr := session.CombinedOutput("provision")
	outStr := string(out)

	if runErr != nil {
		if exitErr, ok := runErr.(*ssh.ExitError); ok {
			return outStr, exitErr.ExitStatus(), nil
		}
		return outStr, -1, runErr
	}
	return outStr, 0, nil
}

func TestTokenProvisioning_FullSuccess(t *testing.T) {
	srv, tmpDir := testServer(t)

	var approvalCalled, issuanceCalled, auditCalled bool

	setTokenProvisioningHooks(srv, TokenProvisioningHooks{
		Approve: func(identityID, sshFingerprint, remoteAddr string) (bool, error) {
			approvalCalled = true
			return true, nil
		},
		Issue: func(identityID string) (string, error) {
			issuanceCalled = true
			return "test-token-value", nil
		},
		AuditProvisioned: func(identityID, sshFingerprint, remoteAddr string) {
			auditCalled = true
		},
	})

	clientSigner, _ := generateClientKey(t)
	output, exitCode, err := runProvisioningSession(t, srv, clientSigner)
	if err != nil {
		t.Fatalf("session error: %v", err)
	}

	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d; output: %s", exitCode, output)
	}
	if !strings.Contains(output, "test-token-value") {
		t.Errorf("expected token in output, got: %s", output)
	}
	if !approvalCalled {
		t.Error("approval callback not called")
	}
	if !issuanceCalled {
		t.Error("issuance callback not called")
	}
	if !auditCalled {
		t.Error("audit callback not called")
	}

	// Verify key was enrolled in authorized_keys
	authKeysData, readErr := os.ReadFile(filepath.Join(tmpDir, "authorized_keys"))
	if readErr != nil {
		t.Fatalf("read authorized_keys: %v", readErr)
	}
	if len(authKeysData) == 0 {
		t.Error("authorized_keys is empty — key was not enrolled")
	}
}

func TestRegisterAuthorizedKeyConcurrentDuplicate(t *testing.T) {
	srv, tmpDir := testServer(t)
	_, pub := generateClientKey(t)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.registerAuthorizedKey(pub); err != nil {
				t.Errorf("registerAuthorizedKey() error = %v", err)
			}
		}()
	}
	wg.Wait()

	authKeysData, err := os.ReadFile(filepath.Join(tmpDir, "authorized_keys"))
	if err != nil {
		t.Fatalf("ReadFile(authorized_keys) error = %v", err)
	}
	lines := strings.Fields(strings.TrimSpace(string(authKeysData)))
	if len(lines) == 0 {
		t.Fatal("authorized_keys is empty")
	}
	if got := strings.Count(string(authKeysData), string(ssh.MarshalAuthorizedKey(pub))); got != 1 {
		t.Fatalf("authorized_keys contains key %d times, want 1", got)
	}
	srv.authKeysMu.RLock()
	authKeyCount := len(srv.authKeys)
	srv.authKeysMu.RUnlock()
	if authKeyCount != 1 {
		t.Fatalf("len(authKeys) = %d, want 1", authKeyCount)
	}
}

func TestRegisterAuthorizedKeyAdoptsExistingFileEntry(t *testing.T) {
	srv, tmpDir := testServer(t)
	_, pub := generateClientKey(t)
	authKeysPath := filepath.Join(tmpDir, "authorized_keys")
	keyLine := string(ssh.MarshalAuthorizedKey(pub))
	if err := os.WriteFile(authKeysPath, []byte(keyLine), 0o600); err != nil {
		t.Fatalf("WriteFile(authorized_keys) error = %v", err)
	}

	if err := srv.registerAuthorizedKey(pub); err != nil {
		t.Fatalf("registerAuthorizedKey() error = %v", err)
	}

	authKeysData, err := os.ReadFile(authKeysPath)
	if err != nil {
		t.Fatalf("ReadFile(authorized_keys) error = %v", err)
	}
	if got := strings.Count(string(authKeysData), keyLine); got != 1 {
		t.Fatalf("authorized_keys contains key %d times, want 1", got)
	}
	srv.authKeysMu.RLock()
	authKeyCount := len(srv.authKeys)
	srv.authKeysMu.RUnlock()
	if authKeyCount != 1 {
		t.Fatalf("len(authKeys) = %d, want 1", authKeyCount)
	}
}

func TestTokenProvisioningApprovalCanceledOnClientDisconnect(t *testing.T) {
	srv, _ := testServer(t)
	clientSigner, _ := generateClientKey(t)

	approvalStarted := make(chan struct{})
	approvalDone := make(chan error, 1)
	setTokenProvisioningHooks(srv, TokenProvisioningHooks{
		ApproveContext: func(ctx context.Context, identityID, sshFingerprint, remoteAddr string) (bool, error) {
			close(approvalStarted)
			<-ctx.Done()
			approvalDone <- ctx.Err()
			return false, ctx.Err()
		},
		Issue: func(identityID string) (string, error) {
			t.Fatal("issuance callback should not be called after client disconnect")
			return "", nil
		},
	})

	ln, listenErr := net.Listen("tcp", "127.0.0.1:0")
	if listenErr != nil {
		t.Fatalf("listen: %v", listenErr)
	}
	defer func() { _ = ln.Close() }()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		sshServerConn, chans, globalReqs, sshErr := ssh.NewServerConn(conn, srv.sshConfig)
		if sshErr != nil {
			return
		}
		defer func() { _ = sshServerConn.Close() }()
		go ssh.DiscardRequests(globalReqs)

		for newChannel := range chans {
			srv.handleTokenProvisioningChannel(context.Background(), sshServerConn, newChannel)
		}
	}()

	clientConfig := &ssh.ClientConfig{
		User: "request-token:default",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(clientSigner),
		},
		HostKeyCallback: ssh.FixedHostKey(srv.hostKey.PublicKey()),
		Timeout:         5 * time.Second,
	}
	clientConn, dialErr := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if dialErr != nil {
		t.Fatalf("dial: %v", dialErr)
	}
	cc, chans, reqs, connErr := ssh.NewClientConn(clientConn, ln.Addr().String(), clientConfig)
	if connErr != nil {
		_ = clientConn.Close()
		t.Fatalf("client connect: %v", connErr)
	}
	client := ssh.NewClient(cc, chans, reqs)
	session, sessErr := client.NewSession()
	if sessErr != nil {
		_ = client.Close()
		t.Fatalf("new session: %v", sessErr)
	}
	if err := session.Start("provision"); err != nil {
		_ = session.Close()
		_ = client.Close()
		t.Fatalf("start provisioning: %v", err)
	}

	select {
	case <-approvalStarted:
	case <-time.After(time.Second):
		t.Fatal("approval callback did not start")
	}
	_ = session.Close()
	_ = client.Close()
	_ = clientConn.Close()

	select {
	case err := <-approvalDone:
		if err == nil {
			t.Fatal("approval context error = nil, want cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("approval callback was not canceled after client disconnect")
	}

	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("server did not finish after client disconnect")
	}
}

func TestClientRequestTokenContextCancelClosesProvisioning(t *testing.T) {
	srv, tmpDir := testServer(t)

	approvalStarted := make(chan struct{})
	approvalDone := make(chan error, 1)
	setTokenProvisioningHooks(srv, TokenProvisioningHooks{
		ApproveContext: func(ctx context.Context, identityID, sshFingerprint, remoteAddr string) (bool, error) {
			close(approvalStarted)
			<-ctx.Done()
			approvalDone <- ctx.Err()
			return false, ctx.Err()
		},
		Issue: func(identityID string) (string, error) {
			t.Fatal("issuance callback should not be called after client cancellation")
			return "", nil
		},
	})

	serverCtx, stopServer := context.WithCancel(context.Background())
	defer stopServer()
	if err := srv.Start(serverCtx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() { _ = srv.Stop() }()

	_, _, identityPath := generateClientIdentityFile(t, tmpDir)
	host, port := splitHostPort(t, srv.listener.Addr().String())
	knownHostsPath := filepath.Join(tmpDir, "known_hosts")
	line := knownhosts.Line([]string{hostWithPort(host, port)}, srv.hostKey.PublicKey()) + "\n"
	if err := os.WriteFile(knownHostsPath, []byte(line), 0600); err != nil {
		t.Fatalf("WriteFile(known_hosts) error = %v", err)
	}

	client := NewClient(host, port, 0, 0, identityPath, knownHostsPath)
	reqCtx, cancelReq := context.WithCancel(context.Background())
	resultCh := make(chan error, 1)
	go func() {
		token, err := client.RequestToken(reqCtx, "default")
		if token != "" {
			resultCh <- fmt.Errorf("token = %q, want empty", token)
			return
		}
		resultCh <- err
	}()

	select {
	case <-approvalStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("approval callback did not start")
	}
	cancelReq()

	select {
	case err := <-resultCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("RequestToken() error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RequestToken() did not return after cancellation")
	}
	select {
	case err := <-approvalDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("approval context error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server approval context was not canceled")
	}
}

func TestTokenProvisioningIgnoresClientStdinEOF(t *testing.T) {
	srv, _ := testServer(t)
	clientSigner, _ := generateClientKey(t)

	approvalStarted := make(chan struct{})
	allowApproval := make(chan struct{})
	approvalCanceled := make(chan error, 1)
	setTokenProvisioningHooks(srv, TokenProvisioningHooks{
		ApproveContext: func(ctx context.Context, identityID, sshFingerprint, remoteAddr string) (bool, error) {
			close(approvalStarted)
			select {
			case <-allowApproval:
				return true, nil
			case <-ctx.Done():
				approvalCanceled <- ctx.Err()
				return false, ctx.Err()
			}
		},
		Issue: func(identityID string) (string, error) {
			return "token-after-stdin-eof", nil
		},
		AuditProvisioned: func(identityID, sshFingerprint, remoteAddr string) {},
	})

	ln, listenErr := net.Listen("tcp", "127.0.0.1:0")
	if listenErr != nil {
		t.Fatalf("listen: %v", listenErr)
	}
	defer func() { _ = ln.Close() }()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		sshServerConn, chans, globalReqs, sshErr := ssh.NewServerConn(conn, srv.sshConfig)
		if sshErr != nil {
			return
		}
		defer func() { _ = sshServerConn.Close() }()
		go ssh.DiscardRequests(globalReqs)

		for newChannel := range chans {
			srv.handleTokenProvisioningChannel(context.Background(), sshServerConn, newChannel)
		}
	}()

	clientConfig := &ssh.ClientConfig{
		User: "request-token:default",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(clientSigner),
		},
		HostKeyCallback: ssh.FixedHostKey(srv.hostKey.PublicKey()),
		Timeout:         5 * time.Second,
	}
	clientConn, dialErr := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if dialErr != nil {
		t.Fatalf("dial: %v", dialErr)
	}
	cc, chans, reqs, connErr := ssh.NewClientConn(clientConn, ln.Addr().String(), clientConfig)
	if connErr != nil {
		_ = clientConn.Close()
		t.Fatalf("client connect: %v", connErr)
	}
	client := ssh.NewClient(cc, chans, reqs)
	session, sessErr := client.NewSession()
	if sessErr != nil {
		_ = client.Close()
		_ = clientConn.Close()
		t.Fatalf("new session: %v", sessErr)
	}
	stdin, stdinErr := session.StdinPipe()
	if stdinErr != nil {
		_ = session.Close()
		_ = client.Close()
		_ = clientConn.Close()
		t.Fatalf("stdin pipe: %v", stdinErr)
	}
	stdout, stdoutErr := session.StdoutPipe()
	if stdoutErr != nil {
		_ = session.Close()
		_ = client.Close()
		_ = clientConn.Close()
		t.Fatalf("stdout pipe: %v", stdoutErr)
	}
	if err := session.Start("provision"); err != nil {
		_ = session.Close()
		_ = client.Close()
		_ = clientConn.Close()
		t.Fatalf("start provisioning: %v", err)
	}

	select {
	case <-approvalStarted:
	case <-time.After(time.Second):
		t.Fatal("approval callback did not start")
	}
	if err := stdin.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}
	select {
	case err := <-approvalCanceled:
		t.Fatalf("approval context canceled after stdin EOF: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	close(allowApproval)
	output, readErr := io.ReadAll(stdout)
	if readErr != nil {
		t.Fatalf("read stdout: %v", readErr)
	}
	if err := session.Wait(); err != nil {
		t.Fatalf("wait provisioning: %v; output: %s", err, string(output))
	}
	if !strings.Contains(string(output), "token-after-stdin-eof") {
		t.Fatalf("output = %q, want token", string(output))
	}

	_ = session.Close()
	_ = client.Close()
	_ = clientConn.Close()
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("server did not finish after client close")
	}
}

func TestTokenProvisioningDeliveryFailureAfterEnrollmentDoesNotAuditSuccess(t *testing.T) {
	srv, tmpDir := testServer(t)
	clientSigner, clientPubKey := generateClientKey(t)

	issueStarted := make(chan struct{})
	allowIssue := make(chan struct{})
	var auditCalled bool
	setTokenProvisioningHooks(srv, TokenProvisioningHooks{
		ApproveContext: func(ctx context.Context, identityID, sshFingerprint, remoteAddr string) (bool, error) {
			return true, nil
		},
		Issue: func(identityID string) (string, error) {
			close(issueStarted)
			<-allowIssue
			return "token-after-client-disconnect", nil
		},
		AuditProvisioned: func(identityID, sshFingerprint, remoteAddr string) {
			auditCalled = true
		},
	})

	ln, listenErr := net.Listen("tcp", "127.0.0.1:0")
	if listenErr != nil {
		t.Fatalf("listen: %v", listenErr)
	}
	defer func() { _ = ln.Close() }()

	serverDone := make(chan struct{})
	connCanceled := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		sshServerConn, chans, globalReqs, sshErr := ssh.NewServerConn(conn, srv.sshConfig)
		if sshErr != nil {
			return
		}
		defer func() { _ = sshServerConn.Close() }()
		go ssh.DiscardRequests(globalReqs)

		connCtx, cancelConnCtx := context.WithCancel(context.Background())
		var handlers sync.WaitGroup
		for newChannel := range chans {
			handlers.Add(1)
			go func(ch ssh.NewChannel) {
				defer handlers.Done()
				srv.handleTokenProvisioningChannel(connCtx, sshServerConn, ch)
			}(newChannel)
		}
		cancelConnCtx()
		close(connCanceled)
		handlers.Wait()
	}()

	clientConfig := &ssh.ClientConfig{
		User: "request-token:default",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(clientSigner),
		},
		HostKeyCallback: ssh.FixedHostKey(srv.hostKey.PublicKey()),
		Timeout:         5 * time.Second,
	}
	clientConn, dialErr := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if dialErr != nil {
		t.Fatalf("dial: %v", dialErr)
	}
	cc, chans, reqs, connErr := ssh.NewClientConn(clientConn, ln.Addr().String(), clientConfig)
	if connErr != nil {
		_ = clientConn.Close()
		t.Fatalf("client connect: %v", connErr)
	}
	client := ssh.NewClient(cc, chans, reqs)
	session, sessErr := client.NewSession()
	if sessErr != nil {
		_ = client.Close()
		_ = clientConn.Close()
		t.Fatalf("new session: %v", sessErr)
	}
	stdout, stdoutErr := session.StdoutPipe()
	if stdoutErr != nil {
		_ = session.Close()
		_ = client.Close()
		_ = clientConn.Close()
		t.Fatalf("stdout pipe: %v", stdoutErr)
	}
	if err := session.Start("provision"); err != nil {
		_ = session.Close()
		_ = client.Close()
		_ = clientConn.Close()
		t.Fatalf("start provisioning: %v", err)
	}

	select {
	case <-issueStarted:
	case <-time.After(time.Second):
		t.Fatal("issuance callback did not start")
	}

	authKeysData, readErr := os.ReadFile(filepath.Join(tmpDir, "authorized_keys"))
	if readErr != nil {
		t.Fatalf("read authorized_keys: %v", readErr)
	}
	keyLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(clientPubKey)))
	if !strings.Contains(string(authKeysData), keyLine) {
		t.Fatalf("authorized_keys does not contain enrolled client key:\n%s", string(authKeysData))
	}

	_ = session.Close()
	_ = client.Close()
	_ = clientConn.Close()
	select {
	case <-connCanceled:
	case <-time.After(time.Second):
		t.Fatal("server did not observe client disconnect")
	}
	close(allowIssue)
	_, _ = io.ReadAll(stdout)

	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("server did not finish after client disconnect")
	}
	if auditCalled {
		t.Fatal("audit callback should not be called after token delivery failure")
	}
}

func TestTokenProvisioning_AllowsNonProductIdentity(t *testing.T) {
	srv, _ := testServer(t)
	_, pub := generateClientKey(t)

	_, err := srv.handleTokenProvisioningAuth(nil, pub, "request-token:other-identity", "127.0.0.1:1", "fp")
	if err != nil {
		t.Fatalf("handleTokenProvisioningAuth(non-product) error = %v", err)
	}
}

func TestTokenProvisioningRejectsUnsupportedIdentity(t *testing.T) {
	srv, _ := testServer(t)
	_, pub := generateClientKey(t)

	var gotIdentityID string
	setTokenProvisioningHooks(srv, TokenProvisioningHooks{
		IdentityProvisioning: func(identityID string) bool {
			gotIdentityID = identityID
			return false
		},
	})

	_, err := srv.handleTokenProvisioningAuth(nil, pub, "request-token:other-identity", "127.0.0.1:1", "fp")
	if err == nil {
		t.Fatal("handleTokenProvisioningAuth() error = nil, want unsupported identity")
	}
	if !strings.Contains(err.Error(), "unsupported identity") {
		t.Fatalf("handleTokenProvisioningAuth() error = %v, want unsupported identity", err)
	}
	if gotIdentityID != "other-identity" {
		t.Fatalf("identity check got %q, want other-identity", gotIdentityID)
	}
}

func TestTokenProvisioningRechecksUnsupportedIdentityOnExec(t *testing.T) {
	srv, _ := testServer(t)
	clientSigner, _ := generateClientKey(t)

	var checks int
	setTokenProvisioningHooks(srv, TokenProvisioningHooks{
		IdentityProvisioning: func(identityID string) bool {
			checks++
			return checks == 1
		},
		Approve: func(identityID, sshFingerprint, remoteAddr string) (bool, error) {
			t.Fatal("approval callback should not be called after exec-time identity rejection")
			return false, nil
		},
		Issue: func(identityID string) (string, error) {
			t.Fatal("issuance callback should not be called after exec-time identity rejection")
			return "", nil
		},
		AuditProvisioned: func(identityID, sshFingerprint, remoteAddr string) {},
	})

	output, exitCode, err := runProvisioningSessionForIdentity(t, srv, clientSigner, "other-identity")
	if err != nil {
		t.Fatalf("session error: %v", err)
	}
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit for exec-time unsupported identity, got output:\n%s", output)
	}
	if !strings.Contains(output, "unsupported identity") {
		t.Fatalf("expected unsupported identity output, got:\n%s", output)
	}
	if checks != 2 {
		t.Fatalf("identity checks = %d, want 2", checks)
	}
}

func TestTokenProvisioning_Rejected(t *testing.T) {
	srv, tmpDir := testServer(t)

	var issuanceCalled, auditCalled bool

	setTokenProvisioningHooks(srv, TokenProvisioningHooks{
		Approve: func(identityID, sshFingerprint, remoteAddr string) (bool, error) {
			return false, nil // Operator rejects
		},
		Issue: func(identityID string) (string, error) {
			issuanceCalled = true
			return "should-not-be-issued", nil
		},
		AuditProvisioned: func(identityID, sshFingerprint, remoteAddr string) {
			auditCalled = true
		},
	})

	clientSigner, _ := generateClientKey(t)
	output, exitCode, err := runProvisioningSession(t, srv, clientSigner)
	if err != nil {
		t.Fatalf("session error: %v", err)
	}

	if exitCode == 0 {
		t.Errorf("expected non-zero exit, got 0; output: %s", output)
	}
	if issuanceCalled {
		t.Error("issuance callback should NOT have been called after rejection")
	}
	if auditCalled {
		t.Error("audit callback should NOT have been called after rejection")
	}

	// Verify no key was enrolled
	authKeysData, _ := os.ReadFile(filepath.Join(tmpDir, "authorized_keys"))
	if len(authKeysData) > 0 {
		t.Error("authorized_keys should be empty after rejection")
	}
}

func TestTokenProvisioning_EnrollmentFailure(t *testing.T) {
	srv, tmpDir := testServer(t)

	// Make authorized_keys path unwritable to force enrollment failure
	authKeysDir := filepath.Join(tmpDir, "nowrite")
	if err := os.MkdirAll(authKeysDir, 0500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	srv.authorizedKeysPath = filepath.Join(authKeysDir, "subdir", "authorized_keys")

	var issuanceCalled, auditCalled bool

	setTokenProvisioningHooks(srv, TokenProvisioningHooks{
		Approve: func(identityID, sshFingerprint, remoteAddr string) (bool, error) {
			return true, nil // Operator approves
		},
		Issue: func(identityID string) (string, error) {
			issuanceCalled = true
			return "should-not-be-issued", nil
		},
		AuditProvisioned: func(identityID, sshFingerprint, remoteAddr string) {
			auditCalled = true
		},
	})

	clientSigner, _ := generateClientKey(t)
	output, exitCode, err := runProvisioningSession(t, srv, clientSigner)
	if err != nil {
		t.Fatalf("session error: %v", err)
	}

	if exitCode == 0 {
		t.Errorf("expected non-zero exit on enrollment failure, got 0; output: %s", output)
	}
	if issuanceCalled {
		t.Error("issuance callback should NOT have been called after enrollment failure")
	}
	if auditCalled {
		t.Error("audit callback should NOT have been called after enrollment failure")
	}
}

func TestTokenProvisioning_IssuanceFailure(t *testing.T) {
	srv, tmpDir := testServer(t)

	var auditCalled bool

	setTokenProvisioningHooks(srv, TokenProvisioningHooks{
		Approve: func(identityID, sshFingerprint, remoteAddr string) (bool, error) {
			return true, nil
		},
		Issue: func(identityID string) (string, error) {
			return "", fmt.Errorf("disk full")
		},
		AuditProvisioned: func(identityID, sshFingerprint, remoteAddr string) {
			auditCalled = true
		},
	})

	clientSigner, _ := generateClientKey(t)
	output, exitCode, err := runProvisioningSession(t, srv, clientSigner)
	if err != nil {
		t.Fatalf("session error: %v", err)
	}

	if exitCode == 0 {
		t.Errorf("expected non-zero exit on issuance failure, got 0; output: %s", output)
	}
	if !strings.Contains(output, "disk full") {
		t.Errorf("expected error message in output, got: %s", output)
	}
	if auditCalled {
		t.Error("audit callback should NOT have been called after issuance failure")
	}

	// Key should still be enrolled (that succeeded before issuance was attempted)
	authKeysData, _ := os.ReadFile(filepath.Join(tmpDir, "authorized_keys"))
	if len(authKeysData) == 0 {
		t.Error("authorized_keys should contain the enrolled key even after issuance failure")
	}
}

func TestTokenProvisioning_NoOperator(t *testing.T) {
	srv, _ := testServer(t)

	var approvalCalled bool

	setTokenProvisioningHooks(srv, TokenProvisioningHooks{
		OperatorConnected: func(identityID string) bool { return false },
		Approve: func(identityID, sshFingerprint, remoteAddr string) (bool, error) {
			approvalCalled = true
			return true, nil
		},
		Issue: func(identityID string) (string, error) {
			return "nope", nil
		},
	})

	clientSigner, _ := generateClientKey(t)
	output, exitCode, err := runProvisioningSession(t, srv, clientSigner)
	if err != nil {
		t.Fatalf("session error: %v", err)
	}

	if exitCode == 0 {
		t.Errorf("expected non-zero exit when no operator, got 0; output: %s", output)
	}
	if approvalCalled {
		t.Error("approval callback should NOT have been called when no operator connected")
	}
}

func TestTokenProvisioningOperatorCheckReceivesIdentity(t *testing.T) {
	srv, _ := testServer(t)

	var gotIdentityID string
	setTokenProvisioningHooks(srv, TokenProvisioningHooks{
		OperatorConnected: func(identityID string) bool {
			gotIdentityID = identityID
			return false
		},
	})

	clientSigner, _ := generateClientKey(t)
	output, exitCode, err := runProvisioningSessionForIdentity(t, srv, clientSigner, "alice")
	if err != nil {
		t.Fatalf("session error: %v", err)
	}
	if exitCode == 0 {
		t.Errorf("expected non-zero exit when no operator, got 0; output: %s", output)
	}
	if gotIdentityID != "alice" {
		t.Fatalf("operator check identityID = %q, want alice", gotIdentityID)
	}
}
