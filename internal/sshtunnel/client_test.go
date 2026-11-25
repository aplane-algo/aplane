// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestKeepaliveStopSignalStopIsConcurrentSafe(t *testing.T) {
	signal := newKeepaliveStopSignal()
	var wg sync.WaitGroup

	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			signal.stop()
		}()
	}
	wg.Wait()

	select {
	case <-signal.done():
	default:
		t.Fatal("stop signal was not closed")
	}

	signal.stop()
}

func TestSSHDialTargetUsesIPv4ForLocalhost(t *testing.T) {
	network, addr := sshDialTarget("tcp", net.JoinHostPort("localhost", "58596"))
	if got, want := network, "tcp4"; got != want {
		t.Fatalf("network = %q, want %q", got, want)
	}
	if got, want := addr, net.JoinHostPort("127.0.0.1", "58596"); got != want {
		t.Fatalf("addr = %q, want %q", got, want)
	}
}

func TestSSHDialTargetPreservesNonLocalhost(t *testing.T) {
	original := net.JoinHostPort("example.com", "58596")
	network, addr := sshDialTarget("tcp", original)
	if got, want := network, "tcp"; got != want {
		t.Fatalf("network = %q, want %q", got, want)
	}
	if got, want := addr, original; got != want {
		t.Fatalf("addr = %q, want %q", got, want)
	}
}

func TestSSHDialTargetPreservesExplicitIPv6(t *testing.T) {
	original := net.JoinHostPort("::1", "58596")
	network, addr := sshDialTarget("tcp", original)
	if got, want := network, "tcp"; got != want {
		t.Fatalf("network = %q, want %q", got, want)
	}
	if got, want := addr, original; got != want {
		t.Fatalf("addr = %q, want %q", got, want)
	}
}

func TestClientResetCloseSignalAllowsReuseAfterClose(t *testing.T) {
	client := NewClient("example.com", 22, "", filepath.Join(t.TempDir(), "known_hosts"))
	close(client.closeChan)

	client.mu.Lock()
	client.resetCloseSignalLocked()
	ch := client.closeChan
	client.mu.Unlock()

	select {
	case <-ch:
		t.Fatal("close signal remained closed after reset")
	default:
	}
}

func TestGenerateIdentityKeyDoesNotOverwriteExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519")
	original := []byte("existing key")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatalf("WriteFile(existing) error = %v", err)
	}
	client := NewClient("example.com", 22, path, filepath.Join(t.TempDir(), "known_hosts"))

	if _, err := client.generateIdentityKey(path); err == nil {
		t.Fatal("generateIdentityKey(existing) error = nil, want create-new failure")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(existing) error = %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("existing key overwritten: got %q, want %q", got, original)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(existing) error = %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("existing key mode = %04o, want 0644 unchanged", info.Mode().Perm())
	}
}

func TestHostKeyApprovalIsPerCallback(t *testing.T) {
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	client := NewClient("example.com", 22, "", knownHostsPath)

	calls := 0
	client.SetHostKeyApprovalHandler(func(host string, fingerprint string) (bool, error) {
		calls++
		return true, nil
	})
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error = %v", err)
	}
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}

	first, err := client.hostKeyCallback()
	if err != nil {
		t.Fatalf("hostKeyCallback(first) error = %v", err)
	}
	if err := first("example.com", remote, signer.PublicKey()); err != nil {
		t.Fatalf("first host key callback error = %v", err)
	}
	if err := os.Remove(knownHostsPath); err != nil {
		t.Fatalf("Remove(known_hosts) error = %v", err)
	}

	second, err := client.hostKeyCallback()
	if err != nil {
		t.Fatalf("hostKeyCallback(second) error = %v", err)
	}
	if err := second("example.com", remote, signer.PublicKey()); err != nil {
		t.Fatalf("second host key callback error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("approval calls = %d, want 2 across separate connection attempts", calls)
	}
}

// TestHostKeyApprovalHoldsAcrossRekeys pins that a host key the user
// approved is accepted at every later key exchange of the same connection,
// as a rekey runs the callback again, and that any other key is refused
// there without a second prompt.
func TestHostKeyApprovalHoldsAcrossRekeys(t *testing.T) {
	client := NewClient("example.com", 22, "", filepath.Join(t.TempDir(), "known_hosts"))
	calls := 0
	client.SetHostKeyApprovalHandler(func(string, string) (bool, error) {
		calls++
		return true, nil
	})
	newKey := func() ssh.PublicKey {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewSignerFromKey(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		return signer.PublicKey()
	}
	approvedKey, otherKey := newKey(), newKey()
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}

	callback, err := client.hostKeyCallback()
	if err != nil {
		t.Fatal(err)
	}
	if err := callback("example.com:22", remote, approvedKey); err != nil {
		t.Fatalf("first key exchange error = %v", err)
	}
	if err := callback("example.com:22", remote, approvedKey); err != nil {
		t.Fatalf("rekey with the approved key error = %v, want accepted", err)
	}
	if err := callback("example.com:22", remote, otherKey); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("rekey with another key error = %v, want ErrHostKeyMismatch", err)
	}
	if calls != 1 {
		t.Fatalf("approval calls = %d, want 1 for one connection", calls)
	}
}

func TestHostKeyCallbackReturnsTypedTrustErrors(t *testing.T) {
	_, firstPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	firstSigner, err := ssh.NewSignerFromKey(firstPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, secondPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secondSigner, err := ssh.NewSignerFromKey(secondPrivate)
	if err != nil {
		t.Fatal(err)
	}
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}

	t.Run("unknown", func(t *testing.T) {
		client := NewClient("unknown.example", 22, "", filepath.Join(t.TempDir(), "known_hosts"))
		callback, err := client.hostKeyCallback()
		if err != nil {
			t.Fatal(err)
		}
		if err := callback("unknown.example:22", remote, firstSigner.PublicKey()); !errors.Is(err, ErrUnknownHostKey) {
			t.Fatalf("host callback error = %v, want ErrUnknownHostKey", err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		client := NewClient("pinned.example", 22, "", filepath.Join(t.TempDir(), "known_hosts"))
		client.SetHostKeyApprovalHandler(func(string, string) (bool, error) { return true, nil })
		callback, err := client.hostKeyCallback()
		if err != nil {
			t.Fatal(err)
		}
		if err := callback("pinned.example:22", remote, firstSigner.PublicKey()); err != nil {
			t.Fatal(err)
		}
		callback, err = client.hostKeyCallback()
		if err != nil {
			t.Fatal(err)
		}
		if err := callback("pinned.example:22", remote, secondSigner.PublicKey()); !errors.Is(err, ErrHostKeyMismatch) {
			t.Fatalf("host callback error = %v, want ErrHostKeyMismatch", err)
		}
	})

	t.Run("malformed known hosts", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "known_hosts")
		if err := os.WriteFile(path, []byte("not a known-hosts record\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		client := NewClient("bad.example", 22, "", path)
		_, err := client.hostKeyCallback()
		if !errors.Is(err, ErrKnownHostsFile) {
			t.Fatalf("hostKeyCallback() error = %v, want ErrKnownHostsFile", err)
		}
	})
}

func TestForwardInterceptedGlobalRequestDoesNotBlockWhenFull(t *testing.T) {
	filtered := make(chan *ssh.Request, 1)
	filtered <- &ssh.Request{Type: "queued"}
	done := make(chan struct{}, 1)

	go func() {
		forwardInterceptedGlobalRequest(filtered, &ssh.Request{Type: "overflow"})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("forwardInterceptedGlobalRequest blocked on full channel")
	}
}

func TestInterceptGlobalRequestsDrainsOverflowAndClosesOnDisconnect(t *testing.T) {
	client := NewClient("127.0.0.1", 22, "", "")
	reqs := make(chan *ssh.Request)
	filtered, done := client.interceptGlobalRequests(reqs)

	// Send more than the 16-slot buffer without reading filtered; the
	// interceptor must keep draining reqs instead of stalling the SSH mux.
	sentAll := make(chan struct{})
	go func() {
		defer close(sentAll)
		for i := 0; i < 40; i++ {
			reqs <- &ssh.Request{Type: "custom@example.com"}
		}
		close(reqs)
	}()

	select {
	case <-sentAll:
	case <-time.After(2 * time.Second):
		t.Fatal("interceptor stalled while draining overflow global requests")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("interceptor done channel did not close after reqs closed")
	}

	// Drain buffered items and confirm filtered is closed (not left open).
	for {
		select {
		case _, ok := <-filtered:
			if !ok {
				return
			}
		case <-time.After(2 * time.Second):
			t.Fatal("filteredReqs was not closed on disconnect")
		}
	}
}

func TestDialAndInterceptDrainsManyGlobalRequestsAndClosesCleanly(t *testing.T) {
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
	serverCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), clientPub.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unknown key")
		},
	}
	serverCfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	serverSent := make(chan error, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			serverSent <- acceptErr
			return
		}
		defer func() { _ = conn.Close() }()
		sshConn, chans, reqs, hsErr := ssh.NewServerConn(conn, serverCfg)
		if hsErr != nil {
			serverSent <- hsErr
			return
		}
		go ssh.DiscardRequests(reqs)
		go func() {
			for ch := range chans {
				_ = ch.Reject(ssh.Prohibited, "no channels")
			}
		}()
		// Send >16 global requests (exceeding SSH mux's 16-slot reqs buffer)
		// to verify the client drains without stalling, then close.
		for i := 0; i < 24; i++ {
			if _, _, err := sshConn.SendRequest("noise@example.com", true, nil); err != nil {
				serverSent <- err
				return
			}
		}
		_ = sshConn.Close()
		serverSent <- nil
	}()

	host, port := splitHostPort(t, ln.Addr().String())
	knownHostsPath := filepath.Join(tmpDir, "known_hosts")
	line := knownhosts.Line([]string{hostWithPort(host, port)}, hostSigner.PublicKey()) + "\n"
	if err := os.WriteFile(knownHostsPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	client := NewClient(host, port, identityPath, knownHostsPath)
	authMethod, agentConn, err := client.authMethod(nil)
	if err != nil {
		t.Fatal(err)
	}
	if agentConn != nil {
		defer func() { _ = agentConn.Close() }()
	}
	hkcb, err := client.hostKeyCallback()
	if err != nil {
		t.Fatal(err)
	}
	dialCtx, cancel := context.WithCancel(t.Context())
	sshClient, done, err := client.dialAndIntercept(dialCtx, "tcp", ln.Addr().String(), &ssh.ClientConfig{
		User:            productSSHUsername,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: hkcb,
		Timeout:         5 * time.Second,
	})
	if err != nil {
		cancel()
		t.Fatalf("dialAndIntercept() error = %v", err)
	}
	// Canceling setup ctx must not abort the interceptor or stall draining.
	cancel()

	select {
	case err := <-serverSent:
		if err != nil {
			t.Fatalf("server global-request burst failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server stalled sending >16 global requests (mux blocked)")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("interceptor did not close after SSH connection closed")
	}
	waitDone := make(chan struct{})
	go func() {
		_ = sshClient.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
	case <-time.After(3 * time.Second):
		t.Fatal("sshClient.Wait() did not return after connection closed")
	}
}

// startMockEnrollmentSSHServer serves one enrollment exec session whose custom
// handler controls exact stdout writes, exit status, and channel lifetime.
func startMockEnrollmentSSHServer(t *testing.T, onExec func(ch ssh.Channel)) (host string, port int, identityPath, knownHostsPath string) {
	t.Helper()
	tmpDir := t.TempDir()
	_, _, identityPath = generateClientIdentityFile(t, tmpDir)
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	serverCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, _ ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	serverCfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, chans, reqs, hsErr := ssh.NewServerConn(conn, serverCfg)
		if hsErr != nil {
			return
		}
		go ssh.DiscardRequests(reqs)
		for newCh := range chans {
			if newCh.ChannelType() != "session" {
				_ = newCh.Reject(ssh.UnknownChannelType, "only session")
				continue
			}
			ch, chReqs, chErr := newCh.Accept()
			if chErr != nil {
				return
			}
			go func() {
				defer func() { _ = ch.Close() }()
				for req := range chReqs {
					if req.Type == "exec" {
						if req.WantReply {
							_ = req.Reply(true, nil)
						}
						onExec(ch)
						return
					}
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
			}()
		}
	}()

	host, port = splitHostPort(t, ln.Addr().String())
	knownHostsPath = filepath.Join(tmpDir, "known_hosts")
	line := knownhosts.Line([]string{hostWithPort(host, port)}, hostSigner.PublicKey()) + "\n"
	if err := os.WriteFile(knownHostsPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return host, port, identityPath, knownHostsPath
}

func TestRequestEnrollmentRejectsOversizedReplyWithoutHanging(t *testing.T) {
	serverReleased := make(chan struct{})
	host, port, identityPath, knownHostsPath := startMockEnrollmentSSHServer(t, func(ch ssh.Channel) {
		defer close(serverReleased)
		chunk := bytes.Repeat([]byte("A"), 1024)
		// Stream past maxEnrollmentReplyBytes and deliberately never send
		// exit-status; client must close without waiting for session.Wait().
		for i := 0; i < 64; i++ {
			if _, err := ch.Write(chunk); err != nil {
				return
			}
		}
		// Keep session open until client closes.
		_, _ = io.Copy(io.Discard, ch)
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client := NewClient(host, port, identityPath, knownHostsPath)
	_, err := client.RequestEnrollment(ctx, "")
	if err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("RequestEnrollment() error = %v, want oversized response error", err)
	}
	select {
	case <-serverReleased:
	case <-time.After(2 * time.Second):
		t.Fatal("server session was not released after client rejected oversized reply")
	}
}

func TestRequestEnrollmentEscapesServerErrorWithoutDoubleQuoting(t *testing.T) {
	host, port, identityPath, knownHostsPath := startMockEnrollmentSSHServer(t, func(ch ssh.Channel) {
		_, _ = ch.Write([]byte("ERROR: \"rejected \x1b[2J\u202e\nnow\"\n"))
		_ = sendExitStatus(ch, 1)
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client := NewClient(host, port, identityPath, knownHostsPath)
	_, err := client.RequestEnrollment(ctx, "")
	if err == nil {
		t.Fatal("RequestEnrollment() error = nil, want server error")
	}
	msg := err.Error()
	if strings.ContainsAny(msg, "\x1b\n") || strings.ContainsRune(msg, '\u202e') {
		t.Fatalf("error contains raw control/bidi characters: %q", msg)
	}
	if !strings.Contains(msg, `\x1b[2J`) || !strings.Contains(msg, `\u202e`) {
		t.Fatalf("error did not escape control sequences: %q", msg)
	}
	if strings.HasPrefix(msg, `"`) || strings.Contains(msg, `\"`) {
		t.Fatalf("error was double-quoted: %q", msg)
	}
	if !strings.HasPrefix(msg, `ERROR: "rejected `) {
		t.Fatalf("error lost original ERROR prefix/quotes: %q", msg)
	}
}

func TestRequestEnrollmentEscapesMismatchedFingerprint(t *testing.T) {
	host, port, identityPath, knownHostsPath := startMockEnrollmentSSHServer(t, func(ch ssh.Channel) {
		_, _ = ch.Write([]byte("enrolled SHA256:evil\x1b[31m\u202e\n"))
		_ = sendExitStatus(ch, 0)
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client := NewClient(host, port, identityPath, knownHostsPath)
	_, err := client.RequestEnrollment(ctx, "")
	if err == nil {
		t.Fatal("RequestEnrollment() error = nil, want fingerprint mismatch")
	}
	msg := err.Error()
	if strings.ContainsAny(msg, "\x1b\n") || strings.ContainsRune(msg, '\u202e') {
		t.Fatalf("mismatch error contains raw control characters: %q", msg)
	}
	if !strings.Contains(msg, `SHA256:evil\x1b[31m\u202e`) {
		t.Fatalf("mismatch error = %q, want escaped fingerprint", msg)
	}
}

func TestSafeEnrollmentTextCapsLengthCleanly(t *testing.T) {
	raw := strings.Repeat("\x1b", 120) + strings.Repeat("é", 120)
	got := safeEnrollmentText(raw)
	if !utf8.ValidString(got) {
		t.Fatalf("safeEnrollmentText produced invalid UTF-8: %q", got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("safeEnrollmentText() = %q, want truncation suffix", got)
	}
	if len(got) > maxEnrollmentErrorBytes+3 {
		t.Fatalf("safeEnrollmentText length = %d, want <= %d", len(got), maxEnrollmentErrorBytes+3)
	}
	if strings.ContainsRune(got, '\x1b') {
		t.Fatalf("safeEnrollmentText left raw ESC: %q", got)
	}
	// Ensure no escape sequence was cut mid-token.
	trimmed := strings.TrimSuffix(got, "...")
	if len(trimmed)%len(`\x1b`) != 0 {
		t.Fatalf("safeEnrollmentText split an escape sequence: %q", got)
	}
}
