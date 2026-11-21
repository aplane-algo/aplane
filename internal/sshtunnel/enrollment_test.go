// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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
		// A label is checked when the request is admitted, which refuses
		// it with a reason (validEnrollmentLabel).
		{"enroll bad\x1bescape", "bad\x1bescape", true},
		{"enroll " + strings.Repeat("a", maxEnrollmentLabelBytes+1), strings.Repeat("a", maxEnrollmentLabelBytes+1), true},
	}
	for _, tt := range tests {
		label, ok := parseEnrollmentCommand(tt.command)
		if ok != tt.ok || label != tt.label {
			t.Fatalf("parseEnrollmentCommand(%q) = (%q, %v), want (%q, %v)", tt.command, label, ok, tt.label, tt.ok)
		}
	}
}

// An enrollment request carries a label only of bounded, valid UTF-8 that
// prints as itself on one line, so the operator reads what the client sent:
// printable Unicode, CJK included, is admitted, and control, format and
// other non-printing characters and invalid bytes are not.
func TestValidEnrollmentLabel(t *testing.T) {
	for _, tc := range []struct {
		label string
		ok    bool
	}{
		{"", true}, {"laptop", true}, {"田中のノートPC", true}, {"phone 😀", true},
		{strings.Repeat("a", maxEnrollmentLabelBytes), true},
		{strings.Repeat("a", maxEnrollmentLabelBytes+1), false},
		{"bad\x1bescape", false}, {"bad\x7f", false}, {"bad\xff", false},
		{"bad\u0085c1", false}, {"bad\u202ebidi", false}, {"bad\u200bzero-width", false}, {"bad\u00a0space", false},
	} {
		if got := validEnrollmentLabel(tc.label); got != tc.ok {
			t.Errorf("validEnrollmentLabel(%q) = %v, want %v", tc.label, got, tc.ok)
		}
	}
}

// A request whose label is not one an approver can read as sent is refused
// with the reason, and nothing is recorded.
func TestEnrollment_RefusesAnUnprintableLabel(t *testing.T) {
	for _, label := range []string{"laptop\u202ebidi", "laptop\xff", "lap\u0085top"} {
		srv, _ := testServer(t)
		var requests []string
		setEnrollmentHooks(srv, EnrollmentHooks{Request: pendingHook(&requests)})
		clientSigner, _ := generateClientKey(t)
		output, exitCode, err := runEnrollmentSessionWithCommand(t, srv, clientSigner, "enroll "+label)
		if err != nil {
			t.Fatalf("label %q: session error: %v", label, err)
		}
		if want := "ERROR: " + errInvalidEnrollmentLabel.Error() + "\n"; exitCode == 0 || output != want {
			t.Errorf("label %q: exit %d output %q, want %q", label, exitCode, output, want)
		}
		if len(requests) != 0 {
			t.Errorf("label %q: recorded %q", label, requests)
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
	srv.SetEnrollmentHooks(hooks)
}

// pendingHook records requests and answers that they wait for the operator.
func pendingHook(record *[]string) EnrollmentRequestFunc {
	return func(key ssh.PublicKey, label, _ string) (bool, error) {
		if record != nil {
			*record = append(*record, ssh.FingerprintSHA256(key)+" "+label)
		}
		return true, nil
	}
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
			srv.handleEnrollmentChannel(sshServerConn, newChannel)
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

// Without the product hook a request is refused and nothing is enrolled.
func TestEnrollment_RefusedWithoutProductHook(t *testing.T) {
	srv, _ := testServer(t)

	clientSigner, _ := generateClientKey(t)
	output, exitCode, err := runEnrollmentSessionWithCommand(t, srv, clientSigner, "enroll laptop")
	if err != nil {
		t.Fatalf("session error: %v", err)
	}
	if exitCode == 0 {
		t.Errorf("expected non-zero exit, got 0; output: %s", output)
	}
	if want := "ERROR: failed to record enrollment request\n"; output != want {
		t.Errorf("output = %q, want %q", output, want)
	}
}

// With the product hook a request is recorded with its label and answered
// "pending".
func TestEnrollment_Pending(t *testing.T) {
	srv, _ := testServer(t)
	var requests []string
	setEnrollmentHooks(srv, EnrollmentHooks{Request: pendingHook(&requests)})

	clientSigner, clientPub := generateClientKey(t)
	output, exitCode, err := runEnrollmentSessionWithCommand(t, srv, clientSigner, "enroll laptop")
	if err != nil {
		t.Fatalf("session error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d; output: %s", exitCode, output)
	}
	fingerprint := ssh.FingerprintSHA256(clientPub)
	if want := "pending " + fingerprint + "\n"; output != want {
		t.Errorf("output = %q, want %q", output, want)
	}
	if len(requests) != 1 || requests[0] != fingerprint+" laptop" {
		t.Errorf("recorded requests = %q", requests)
	}
}

// A key the registry already holds is answered "enrolled" without a request.
func TestEnrollment_AlreadyEnrolled(t *testing.T) {
	srv, _ := testServer(t)
	setEnrollmentHooks(srv, EnrollmentHooks{
		Request: func(ssh.PublicKey, string, string) (bool, error) { return false, nil },
	})

	clientSigner, clientPub := generateClientKey(t)
	output, exitCode, err := runEnrollmentSession(t, srv, clientSigner)
	if err != nil {
		t.Fatalf("session error: %v", err)
	}
	if exitCode != 0 || output != "enrolled "+ssh.FingerprintSHA256(clientPub)+"\n" {
		t.Errorf("exit %d output %q", exitCode, output)
	}
}

// A request the product refuses (for example a full queue) is answered with
// the refusal and a non-zero exit.
func TestEnrollment_Refused(t *testing.T) {
	srv, _ := testServer(t)
	setEnrollmentHooks(srv, EnrollmentHooks{
		Request: func(ssh.PublicKey, string, string) (bool, error) {
			return false, fmt.Errorf("enrollment queue is full")
		},
	})

	clientSigner, _ := generateClientKey(t)
	output, exitCode, err := runEnrollmentSession(t, srv, clientSigner)
	if err != nil {
		t.Fatalf("session error: %v", err)
	}
	if exitCode == 0 {
		t.Errorf("expected non-zero exit, got 0; output: %s", output)
	}
	if !strings.Contains(output, "ERROR: ") || !strings.Contains(output, "enrollment queue is full") {
		t.Errorf("output = %q, want the refusal", output)
	}
}

// A refused request reaches the client as the server's ERROR line, which the
// server writes to the session's standard output.
func TestRequestEnrollmentReportsTheRefusalLine(t *testing.T) {
	srv, dir := testServer(t)
	setEnrollmentHooks(srv, EnrollmentHooks{
		Request: func(ssh.PublicKey, string, string) (bool, error) {
			return false, fmt.Errorf("enrollment queue is full")
		},
	})
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
	_, _, identity := generateClientIdentityFile(t, dir)

	result, err := NewClient(host, port, identity, known).RequestEnrollment(ctx, "")
	if err == nil {
		t.Fatalf("RequestEnrollment() = %+v, want the refusal", result)
	}
	if want := `ERROR: "enrollment queue is full"`; err.Error() != want {
		t.Fatalf("RequestEnrollment() error = %q, want %q", err.Error(), want)
	}
}
