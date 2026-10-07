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

func TestEnrollmentPublicKeyHandlesMissingPermissions(t *testing.T) {
	if _, ok := enrollmentPublicKey(nil); ok {
		t.Fatal("enrollmentPublicKey(nil) reported a key")
	}
	if _, ok := enrollmentPublicKey(&ssh.Permissions{}); ok {
		t.Fatal("enrollmentPublicKey(empty extensions) reported a key")
	}
	if _, ok := enrollmentPublicKey(&ssh.Permissions{Extensions: map[string]string{"public_key": "not a key"}}); ok {
		t.Fatal("enrollmentPublicKey(malformed) reported a key")
	}
	_, pub := generateClientKey(t)
	key, ok := enrollmentPublicKey(&ssh.Permissions{Extensions: map[string]string{"public_key": string(ssh.MarshalAuthorizedKey(pub))}})
	if !ok || ssh.FingerprintSHA256(key) != ssh.FingerprintSHA256(pub) {
		t.Fatalf("enrollmentPublicKey() = %v, %v", key, ok)
	}
}

func TestParseEnrollmentCommand(t *testing.T) {
	tests := []struct {
		command string
		label   string
		ok      bool
	}{
		{"enroll", "", true},
		{"enroll laptop", "laptop", true},
		{"enroll  padded label ", "padded label", true},
		{"enroll ", "", false},
		{"enrollx", "", false},
		{"provision", "", false},
		{"enroll bad\x1bescape", "", false},
		{"enroll " + strings.Repeat("a", maxEnrollmentLabelBytes+1), "", false},
	}
	for _, tt := range tests {
		label, ok := parseEnrollmentCommand(tt.command)
		if ok != tt.ok || label != tt.label {
			t.Fatalf("parseEnrollmentCommand(%q) = (%q, %v), want (%q, %v)", tt.command, label, ok, tt.label, tt.ok)
		}
	}
}

// testServer creates a minimal Server for enrollment and channel tests.
func testServer(t *testing.T) (*Server, string) {
	t.Helper()
	tmpDir := t.TempDir()

	hostKeyPath := filepath.Join(tmpDir, "host_key")

	srv, err := NewServer("127.0.0.1:0", hostKeyPath)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	return srv, tmpDir
}

func setEnrollmentHooks(srv *Server, hooks EnrollmentHooks) {
	if hooks.OperatorConnected == nil {
		hooks.OperatorConnected = func() bool { return true }
	}
	srv.SetEnrollmentHooks(hooks)
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

// runEnrollmentSession starts a TCP listener, accepts one connection on the
// server side, and connects with an SSH client to run "enroll".
func runEnrollmentSession(t *testing.T, srv *Server, clientSigner ssh.Signer) (output string, exitCode int, err error) {
	t.Helper()
	return runEnrollmentSessionWithCommand(t, srv, clientSigner, "enroll")
}

func runEnrollmentSessionWithCommand(t *testing.T, srv *Server, clientSigner ssh.Signer, command string) (output string, exitCode int, err error) {
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
			srv.handleEnrollmentChannel(context.Background(), sshServerConn, newChannel)
		}
	}()

	// Client side
	clientConfig := &ssh.ClientConfig{
		User: enrollmentSSHUsername,
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

	out, runErr := session.CombinedOutput(command)
	outStr := string(out)

	if runErr != nil {
		if exitErr, ok := runErr.(*ssh.ExitError); ok {
			return outStr, exitErr.ExitStatus(), nil
		}
		return outStr, -1, runErr
	}
	return outStr, 0, nil
}

func TestEnrollment_FullSuccess(t *testing.T) {
	srv, _ := testServer(t)

	var approvalCalled, auditCalled bool
	var approvedLabel, auditedLabel string
	setEnrollmentHooks(srv, EnrollmentHooks{
		ApproveContext: func(_ context.Context, sshFingerprint, label, remoteAddr string) (bool, error) {
			approvalCalled = true
			approvedLabel = label
			return true, nil
		},
		AuditEnrolled: func(sshFingerprint, label, remoteAddr string) {
			auditCalled = true
			auditedLabel = label
		},
	})

	clientSigner, clientPub := generateClientKey(t)
	output, exitCode, err := runEnrollmentSessionWithCommand(t, srv, clientSigner, "enroll laptop")
	if err != nil {
		t.Fatalf("session error: %v", err)
	}

	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d; output: %s", exitCode, output)
	}
	if want := "enrolled " + ssh.FingerprintSHA256(clientPub) + "\n"; output != want {
		t.Errorf("output = %q, want %q", output, want)
	}
	if !approvalCalled || approvedLabel != "laptop" {
		t.Errorf("approval callback called=%v label=%q", approvalCalled, approvedLabel)
	}
	if !auditCalled || auditedLabel != "laptop" {
		t.Errorf("audit callback called=%v label=%q", auditCalled, auditedLabel)
	}
	if !srv.hasAuthorizedKey(clientPub) {
		t.Error("key was not enrolled")
	}
}

func TestEnrollmentApprovalCanceledOnClientDisconnect(t *testing.T) {
	srv, _ := testServer(t)
	clientSigner, _ := generateClientKey(t)

	approvalStarted := make(chan struct{})
	approvalDone := make(chan error, 1)
	setEnrollmentHooks(srv, EnrollmentHooks{
		ApproveContext: func(ctx context.Context, sshFingerprint, label, remoteAddr string) (bool, error) {
			close(approvalStarted)
			<-ctx.Done()
			approvalDone <- ctx.Err()
			return false, ctx.Err()
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
			srv.handleEnrollmentChannel(context.Background(), sshServerConn, newChannel)
		}
	}()

	clientConfig := &ssh.ClientConfig{
		User: enrollmentSSHUsername,
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
	if err := session.Start("enroll"); err != nil {
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

func TestClientRequestEnrollmentContextCancelClosesRequest(t *testing.T) {
	srv, tmpDir := testServer(t)

	approvalStarted := make(chan struct{})
	approvalDone := make(chan error, 1)
	setEnrollmentHooks(srv, EnrollmentHooks{
		ApproveContext: func(ctx context.Context, sshFingerprint, label, remoteAddr string) (bool, error) {
			close(approvalStarted)
			<-ctx.Done()
			approvalDone <- ctx.Err()
			return false, ctx.Err()
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

	client := NewClient(host, port, 0, identityPath, knownHostsPath)
	reqCtx, cancelReq := context.WithCancel(context.Background())
	resultCh := make(chan error, 1)
	go func() {
		fingerprint, err := client.RequestEnrollment(reqCtx, "")
		if fingerprint != "" {
			resultCh <- fmt.Errorf("fingerprint = %q, want empty", fingerprint)
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
			t.Fatalf("RequestEnrollment() error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RequestEnrollment() did not return after cancellation")
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

func TestEnrollmentIgnoresClientStdinEOF(t *testing.T) {
	srv, _ := testServer(t)
	clientSigner, _ := generateClientKey(t)

	approvalStarted := make(chan struct{})
	allowApproval := make(chan struct{})
	approvalCanceled := make(chan error, 1)
	setEnrollmentHooks(srv, EnrollmentHooks{
		ApproveContext: func(ctx context.Context, sshFingerprint, label, remoteAddr string) (bool, error) {
			close(approvalStarted)
			select {
			case <-allowApproval:
				return true, nil
			case <-ctx.Done():
				approvalCanceled <- ctx.Err()
				return false, ctx.Err()
			}
		},
		AuditEnrolled: func(sshFingerprint, label, remoteAddr string) {},
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
			srv.handleEnrollmentChannel(context.Background(), sshServerConn, newChannel)
		}
	}()

	clientConfig := &ssh.ClientConfig{
		User: enrollmentSSHUsername,
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
	if err := session.Start("enroll"); err != nil {
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
	if !strings.Contains(string(output), "enrolled ") {
		t.Fatalf("output = %q, want the enrollment acknowledgement", string(output))
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

func TestEnrollmentDeliveryFailureAfterEnrollmentDoesNotAuditSuccess(t *testing.T) {
	srv, _ := testServer(t)
	clientSigner, clientPubKey := generateClientKey(t)

	issueStarted := make(chan struct{})
	allowIssue := make(chan struct{})
	var auditCalled, enrolled bool
	setEnrollmentHooks(srv, EnrollmentHooks{
		ApproveContext: func(ctx context.Context, sshFingerprint, label, remoteAddr string) (bool, error) {
			return true, nil
		},
		AuditEnrolled: func(sshFingerprint, label, remoteAddr string) {
			auditCalled = true
		},
	})
	// The registry write succeeds, then the client is gone before the
	// acknowledgement: the enrollment stands, but it is not audited as
	// delivered. The hook blocks so the test controls that ordering.
	srv.SetProductHooks(ProductHooks{
		CheckKey: func(key ssh.PublicKey) bool {
			return enrolled && ssh.FingerprintSHA256(key) == ssh.FingerprintSHA256(clientPubKey)
		},
		EnrollKey: func(key ssh.PublicKey, label string) error {
			enrolled = true
			close(issueStarted)
			<-allowIssue
			return nil
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
				srv.handleEnrollmentChannel(connCtx, sshServerConn, ch)
			}(newChannel)
		}
		cancelConnCtx()
		close(connCanceled)
		handlers.Wait()
	}()

	clientConfig := &ssh.ClientConfig{
		User: enrollmentSSHUsername,
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
	if err := session.Start("enroll"); err != nil {
		_ = session.Close()
		_ = client.Close()
		_ = clientConn.Close()
		t.Fatalf("start provisioning: %v", err)
	}

	select {
	case <-issueStarted:
	case <-time.After(time.Second):
		t.Fatal("enrollment hook did not start")
	}
	if !enrolled {
		t.Fatal("client key was not enrolled")
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
		t.Fatal("audit callback should not be called after acknowledgement delivery failure")
	}
}

func TestEnrollment_Rejected(t *testing.T) {
	srv, _ := testServer(t)

	var auditCalled bool
	setEnrollmentHooks(srv, EnrollmentHooks{
		ApproveContext: func(_ context.Context, sshFingerprint, label, remoteAddr string) (bool, error) {
			return false, nil // Operator rejects
		},
		AuditEnrolled: func(sshFingerprint, label, remoteAddr string) {
			auditCalled = true
		},
	})

	clientSigner, clientPub := generateClientKey(t)
	output, exitCode, err := runEnrollmentSession(t, srv, clientSigner)
	if err != nil {
		t.Fatalf("session error: %v", err)
	}

	if exitCode == 0 {
		t.Errorf("expected non-zero exit, got 0; output: %s", output)
	}
	if !strings.Contains(output, "rejected by operator") {
		t.Errorf("output = %q, want the operator rejection", output)
	}
	if auditCalled {
		t.Error("audit callback should NOT have been called after rejection")
	}
	if srv.hasAuthorizedKey(clientPub) {
		t.Error("key should not be enrolled after rejection")
	}
}

func TestEnrollment_RegistryFailure(t *testing.T) {
	srv, _ := testServer(t)

	var auditCalled bool
	setEnrollmentHooks(srv, EnrollmentHooks{
		ApproveContext: func(_ context.Context, sshFingerprint, label, remoteAddr string) (bool, error) {
			return true, nil // Operator approves
		},
		AuditEnrolled: func(sshFingerprint, label, remoteAddr string) {
			auditCalled = true
		},
	})
	srv.SetProductHooks(ProductHooks{
		CheckKey:  func(key ssh.PublicKey) bool { return false },
		EnrollKey: func(key ssh.PublicKey, label string) error { return fmt.Errorf("registry publish failed") },
	})

	clientSigner, _ := generateClientKey(t)
	output, exitCode, err := runEnrollmentSession(t, srv, clientSigner)
	if err != nil {
		t.Fatalf("session error: %v", err)
	}

	if exitCode == 0 {
		t.Errorf("expected non-zero exit on registry failure, got 0; output: %s", output)
	}
	if !strings.Contains(output, "failed to enroll SSH key") {
		t.Errorf("output = %q, want the enrollment failure", output)
	}
	if auditCalled {
		t.Error("audit callback should NOT have been called after registry failure")
	}
}

func TestEnrollment_NoOperator(t *testing.T) {
	srv, _ := testServer(t)

	var approvalCalled bool

	setEnrollmentHooks(srv, EnrollmentHooks{
		OperatorConnected: func() bool { return false },
		ApproveContext: func(_ context.Context, sshFingerprint, label, remoteAddr string) (bool, error) {
			approvalCalled = true
			return true, nil
		},
	})

	clientSigner, _ := generateClientKey(t)
	output, exitCode, err := runEnrollmentSession(t, srv, clientSigner)
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

func TestEnrollmentChecksProductOperator(t *testing.T) {
	srv, _ := testServer(t)

	called := false
	setEnrollmentHooks(srv, EnrollmentHooks{
		OperatorConnected: func() bool {
			called = true
			return false
		},
	})

	clientSigner, _ := generateClientKey(t)
	output, exitCode, err := runEnrollmentSession(t, srv, clientSigner)
	if err != nil {
		t.Fatalf("session error: %v", err)
	}
	if exitCode == 0 {
		t.Errorf("expected non-zero exit when no operator, got 0; output: %s", output)
	}
	if !called {
		t.Fatal("product operator callback was not called")
	}
}
