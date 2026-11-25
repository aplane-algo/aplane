// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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

	setupEnded := make(chan struct{})
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
		<-setupEnded
		// None of these waits for a reply, so together they overfill the
		// client mux's 16-slot buffer unless the client drains it.
		for i := 0; i < 64; i++ {
			if _, _, err := sshConn.SendRequest("noise@example.com", false, nil); err != nil {
				serverSent <- err
				return
			}
		}
		for _, request := range []struct {
			name string
			want bool
		}{
			{"noise@example.com", false},
			{ConnectionLimitRequestType, true},
			{"noise@example.com", false},
		} {
			ok, _, err := sshConn.SendRequest(request.name, true, nil)
			if err == nil && ok != request.want {
				err = fmt.Errorf("client answered %s with %v, want %v", request.name, ok, request.want)
			}
			if err != nil {
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
	consumersBefore := sshRequestConsumers()
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
	close(setupEnded)

	select {
	case err := <-serverSent:
		if err != nil {
			t.Fatalf("server global-request burst failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the client stopped answering global requests")
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
	if reason := client.DisconnectReason(); reason != DisconnectReasonConnectionLimit {
		t.Fatalf("DisconnectReason() = %q, want the notice the server sent", reason)
	}
	deadline := time.Now().Add(3 * time.Second)
	for sshRequestConsumers() > consumersBefore {
		if time.Now().After(deadline) {
			t.Fatal("ssh.Client's global-request goroutine outlived the connection")
		}
		time.Sleep(time.Millisecond)
	}
}

// sshRequestConsumers counts the goroutines ssh.Client runs to answer global
// requests.
func sshRequestConsumers() int {
	stacks := make([]byte, 1<<20)
	stacks = stacks[:runtime.Stack(stacks, true)]
	return bytes.Count(stacks, []byte("ssh.(*Client).handleGlobalRequests("))
}

// acceptAnyKey is a server config that authenticates every client key.
func acceptAnyKey() *ssh.ServerConfig {
	return &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, _ ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
}

// startMockEnrollmentSSHServer serves one enrollment exec session whose custom
// handler controls exact stdout writes, exit status, and channel lifetime.
func startMockEnrollmentSSHServer(t *testing.T, serverCfg *ssh.ServerConfig, onExec func(ch ssh.Channel)) (host string, port int, identityPath, knownHostsPath string) {
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

// A server that streams without end, and one that goes silent just past the
// cap, are refused at the cap: the client neither reads on nor waits for an
// exit status that never comes.
func TestRequestEnrollmentRejectsOversizedReplyWithoutHanging(t *testing.T) {
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	streamEnded := make(chan struct{})
	servers := map[string]func(ch ssh.Channel){
		"streams without end": func(ch ssh.Channel) {
			defer close(streamEnded)
			chunk := bytes.Repeat([]byte("A"), 1024)
			for {
				if _, err := ch.Write(chunk); err != nil {
					return
				}
			}
		},
		"silent one byte past the cap": func(ch ssh.Channel) {
			_, _ = ch.Write(bytes.Repeat([]byte("A"), maxEnrollmentReplyBytes+1))
			<-hold
		},
	}
	for name, onExec := range servers {
		t.Run(name, func(t *testing.T) {
			host, port, identityPath, knownHostsPath := startMockEnrollmentSSHServer(t, acceptAnyKey(), onExec)
			// Longer than the wait below, so the context never ends the request.
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, err := NewClient(host, port, identityPath, knownHostsPath).RequestEnrollment(ctx, "")
				result <- err
			}()
			select {
			case err := <-result:
				want := fmt.Sprintf("enrollment response exceeded %d bytes", maxEnrollmentReplyBytes)
				if err == nil || err.Error() != want {
					t.Fatalf("RequestEnrollment() error = %v, want %q", err, want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("RequestEnrollment() was still waiting on an oversized reply after 5s")
			}
		})
	}
	select {
	case <-streamEnded:
	case <-time.After(5 * time.Second):
		t.Fatal("the streaming server's session outlived the refused request")
	}
}

// A reply of exactly the cap is read whole.
func TestRequestEnrollmentReadsAReplyOfExactlyTheCap(t *testing.T) {
	host, port, identityPath, knownHostsPath := startMockEnrollmentSSHServer(t, acceptAnyKey(), func(ch ssh.Channel) {
		_, _ = ch.Write(bytes.Repeat([]byte("A"), maxEnrollmentReplyBytes))
		_ = sendExitStatus(ch, 0)
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err := NewClient(host, port, identityPath, knownHostsPath).RequestEnrollment(ctx, "")
	if err == nil || !strings.Contains(err.Error(), "unexpected enrollment response") {
		t.Fatalf("RequestEnrollment() error = %v, want the reply read and refused as unexpected", err)
	}
}

// A server that lets the client in without its key could name any key as
// enrolled, in any text, so nothing is sent to it.
func TestRequestEnrollmentRefusesAServerThatSkipsKeyAuthentication(t *testing.T) {
	var execs atomic.Int32
	host, port, identityPath, knownHostsPath := startMockEnrollmentSSHServer(t, &ssh.ServerConfig{NoClientAuth: true}, func(ch ssh.Channel) {
		execs.Add(1)
		_, _ = ch.Write([]byte("enrolled SHA256:x\x1b[2J\n"))
		_ = sendExitStatus(ch, 0)
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client := NewClient(host, port, identityPath, knownHostsPath)
	started := false
	client.SetEnrollmentStartCallback(func(string) { started = true })
	result, err := client.RequestEnrollment(ctx, "")
	if err == nil || !strings.Contains(err.Error(), "did not authenticate this client's SSH key") {
		t.Fatalf("RequestEnrollment() = (%+v, %v), want a refusal", result, err)
	}
	if result != (EnrollmentResult{}) || started || execs.Load() != 0 {
		t.Fatalf("result=%+v started=%v execs=%d, want none", result, started, execs.Load())
	}
}

// With no reply to show, the error is the exit signal's own text, which the
// server chooses.
func TestRequestEnrollmentEscapesExitSignalText(t *testing.T) {
	host, port, identityPath, knownHostsPath := startMockEnrollmentSSHServer(t, acceptAnyKey(), func(ch ssh.Channel) {
		_, _ = ch.SendRequest("exit-signal", false, ssh.Marshal(struct {
			Signal     string
			CoreDumped bool
			Message    string
			Language   string
		}{Signal: "KI\x1b[31mLL", Message: "bad\x1b[2J\u202e" + strings.Repeat("x", 4*maxEnrollmentErrorBytes)}))
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err := NewClient(host, port, identityPath, knownHostsPath).RequestEnrollment(ctx, "")
	if err == nil {
		t.Fatal("RequestEnrollment() error = nil, want the exit signal")
	}
	msg := err.Error()
	if strings.ContainsRune(msg, '\x1b') || strings.ContainsRune(msg, '\u202e') {
		t.Fatalf("error contains raw control or bidi characters: %q", msg)
	}
	if !strings.HasPrefix(msg, "enrollment failed: ") || !strings.Contains(msg, `KI\x1b[31mLL`) || !strings.Contains(msg, `bad\x1b[2J\u202e`) {
		t.Fatalf("error = %q, want the signal and message escaped", msg)
	}
	if limit := len("enrollment failed: ") + maxEnrollmentErrorBytes + len("..."); len(msg) > limit {
		t.Fatalf("error is %d bytes, want at most %d", len(msg), limit)
	}
}

func TestRequestEnrollmentEscapesServerErrorWithoutDoubleQuoting(t *testing.T) {
	host, port, identityPath, knownHostsPath := startMockEnrollmentSSHServer(t, acceptAnyKey(), func(ch ssh.Channel) {
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
	host, port, identityPath, knownHostsPath := startMockEnrollmentSSHServer(t, acceptAnyKey(), func(ch ssh.Channel) {
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
	// The leading byte puts the cap inside an escape, and inside a rune.
	for name, raw := range map[string]string{
		"escapes": "a" + strings.Repeat("\x1b", 120),
		"runes":   "a" + strings.Repeat("é", 200),
	} {
		t.Run(name, func(t *testing.T) {
			got := safeEnrollmentText(raw)
			if !utf8.ValidString(got) {
				t.Fatalf("safeEnrollmentText produced invalid UTF-8: %q", got)
			}
			text, cut := strings.CutSuffix(got, "...")
			if !cut || len(text) > maxEnrollmentErrorBytes {
				t.Fatalf("safeEnrollmentText() = %d bytes of text, cut=%v, want at most %d and a mark", len(text), cut, maxEnrollmentErrorBytes)
			}
			if strings.ContainsRune(got, '\x1b') {
				t.Fatalf("safeEnrollmentText left raw ESC: %q", got)
			}
			unit := `\x1b`
			if name == "runes" {
				unit = "é"
			}
			if rest := strings.TrimPrefix(text, "a"); strings.Repeat(unit, len(rest)/len(unit)) != rest {
				t.Fatalf("safeEnrollmentText cut %s in half: %q", unit, text)
			}
		})
	}
	short := `ERROR: "invalid label"`
	if got := safeEnrollmentText(short); got != short {
		t.Fatalf("safeEnrollmentText(%q) = %q, want it unchanged", short, got)
	}
}
