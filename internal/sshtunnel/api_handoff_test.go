// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// enrolledSet is a product registry stand-in whose membership tests can
// change while connections are live.
type enrolledSet struct {
	mu   sync.Mutex
	keys map[string]bool
}

func newEnrolledSet() *enrolledSet { return &enrolledSet{keys: make(map[string]bool)} }

func (s *enrolledSet) hooks() ProductHooks {
	return ProductHooks{
		CheckKey: func(key ssh.PublicKey) bool {
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.keys[ssh.FingerprintSHA256(key)]
		},
		EnrollKey: func(key ssh.PublicKey, _ string) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.keys[ssh.FingerprintSHA256(key)] = true
			return nil
		},
	}
}

func (s *enrolledSet) add(key ssh.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[ssh.FingerprintSHA256(key)] = true
}

func (s *enrolledSet) remove(fingerprint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, fingerprint)
}

// startServer starts srv, pins its host key in a known_hosts file, and
// returns the address clients should use.
func startServer(t *testing.T, srv *Server, tmpDir string) (host string, port int, knownHostsPath string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })
	host, port = splitHostPort(t, srv.listener.Addr().String())
	knownHostsPath = filepath.Join(tmpDir, "known_hosts")
	line := knownhosts.Line([]string{hostWithPort(host, port)}, srv.hostKey.PublicKey()) + "\n"
	if err := os.WriteFile(knownHostsPath, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	return host, port, knownHostsPath
}

func connectEnrolledClient(t *testing.T, srv *Server, set *enrolledSet, tmpDir, host string, port int, knownHostsPath string) (*Client, string) {
	t.Helper()
	_ = tmpDir
	_, pub, identityPath := generateClientIdentityFile(t, t.TempDir())
	set.add(pub)
	client := NewClient(host, port, 0, identityPath, knownHostsPath)
	if err := client.ConnectWithKey(context.Background()); err != nil {
		t.Fatalf("ConnectWithKey() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, ssh.FingerprintSHA256(pub)
}

// An API channel reaches the handoff as a connection that names the enrolled
// key that opened it and the SSH peer's address, and carries bytes both ways.
func TestAPIChannelCarriesClientIdentity(t *testing.T) {
	srv, tmpDir := testServer(t)
	set := newEnrolledSet()
	srv.SetProductHooks(set.hooks())
	handed := make(chan *APIConn, 1)
	srv.SetAPIHandoff(func(conn *APIConn) error {
		handed <- conn
		go func() {
			defer func() { _ = conn.Close() }()
			line, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("echo " + line))
		}()
		return nil
	})
	host, port, known := startServer(t, srv, tmpDir)
	client, fingerprint := connectEnrolledClient(t, srv, set, tmpDir, host, port, known)

	conn, err := client.DialSignerAPI(context.Background())
	if err != nil {
		t.Fatalf("DialSignerAPI() error = %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || reply != "echo hello\n" {
		t.Fatalf("reply = %q, %v", reply, err)
	}

	select {
	case api := <-handed:
		if api.KeyFingerprint() != fingerprint {
			t.Fatalf("KeyFingerprint() = %q, want %q", api.KeyFingerprint(), fingerprint)
		}
		if api.RemoteAddr() == nil || !strings.HasPrefix(api.RemoteAddr().String(), "127.0.0.1:") {
			t.Fatalf("RemoteAddr() = %v, want the SSH peer", api.RemoteAddr())
		}
		if api.LocalAddr() == nil || api.LocalAddr().String() != srv.listener.Addr().String() {
			t.Fatalf("LocalAddr() = %v, want the SSH listener", api.LocalAddr())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("API connection was not handed off")
	}
}

// Without a handoff, or when the handoff refuses, the channel is rejected
// rather than accepted and dropped.
func TestAPIChannelRefusedWithoutHandoff(t *testing.T) {
	for _, tt := range []struct {
		name    string
		handoff APIHandoff
	}{
		{name: "no handoff", handoff: nil},
		{name: "handoff refuses", handoff: func(*APIConn) error { return errors.New("full") }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv, tmpDir := testServer(t)
			set := newEnrolledSet()
			srv.SetProductHooks(set.hooks())
			if tt.handoff != nil {
				srv.SetAPIHandoff(tt.handoff)
			}
			host, port, known := startServer(t, srv, tmpDir)
			client, _ := connectEnrolledClient(t, srv, set, tmpDir, host, port, known)
			_, err := client.DialSignerAPI(context.Background())
			var openErr *ssh.OpenChannelError
			if !errors.As(err, &openErr) {
				t.Fatalf("DialSignerAPI() error = %v, want an open-channel rejection", err)
			}
		})
	}
}

// Revoking one key closes that key's connections, tells the client why, and
// leaves other clients connected.
func TestCloseConnectionsForFingerprintClosesOnlyThatKey(t *testing.T) {
	srv, tmpDir := testServer(t)
	set := newEnrolledSet()
	srv.SetProductHooks(set.hooks())
	srv.SetAPIHandoff(func(conn *APIConn) error { _ = conn.Close(); return nil })
	host, port, known := startServer(t, srv, tmpDir)
	revokedClient, revokedFP := connectEnrolledClient(t, srv, set, tmpDir, host, port, known)
	keptClient, _ := connectEnrolledClient(t, srv, set, tmpDir, host, port, known)

	disconnected := make(chan struct{})
	revokedClient.SetDisconnectCallback(func() { close(disconnected) })

	set.remove(revokedFP)
	if n := srv.CloseConnectionsForFingerprint(revokedFP, "key revoked"); n != 1 {
		t.Fatalf("CloseConnectionsForFingerprint() = %d, want 1", n)
	}
	select {
	case <-disconnected:
	case <-time.After(3 * time.Second):
		t.Fatal("revoked client was not disconnected")
	}
	revokedClient.mu.Lock()
	reason := revokedClient.disconnectReason
	revokedClient.mu.Unlock()
	if reason != DisconnectReasonKeyRevoked {
		t.Fatalf("disconnect reason = %q, want %q", reason, DisconnectReasonKeyRevoked)
	}
	if !keptClient.IsConnected() {
		t.Fatal("unrelated client was disconnected")
	}
	if err := revokedClient.ConnectWithKey(context.Background()); err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
		t.Fatalf("reconnect after revocation error = %v, want authentication failure", err)
	}
	if srv.ActiveConnectionCount() != 1 {
		t.Fatalf("ActiveConnectionCount() = %d, want 1", srv.ActiveConnectionCount())
	}
}

// A key revoked after SSH accepted it but before the connection is tracked
// is refused at tracking time, so the revocation's close pass cannot miss it.
func TestKeyRevokedDuringHandshakeIsRefused(t *testing.T) {
	srv, tmpDir := testServer(t)
	set := newEnrolledSet()
	srv.SetProductHooks(set.hooks())
	srv.SetAPIHandoff(func(conn *APIConn) error { _ = conn.Close(); return nil })
	_, pub, identityPath := generateClientIdentityFile(t, tmpDir)
	set.add(pub)
	srv.testAfterAuthBeforeTrack = func() { set.remove(ssh.FingerprintSHA256(pub)) }
	host, port, known := startServer(t, srv, tmpDir)

	client := NewClient(host, port, 0, identityPath, known)
	// The SSH handshake itself succeeds; the server then refuses the
	// connection, which the client observes as a prompt disconnect.
	disconnected := make(chan struct{})
	client.SetDisconnectCallback(func() { close(disconnected) })
	if err := client.ConnectWithKey(context.Background()); err != nil {
		if strings.Contains(err.Error(), "unable to authenticate") {
			t.Fatalf("ConnectWithKey() failed at authentication, but revocation happened after it: %v", err)
		}
		return // refused before the client finished connecting; also acceptable
	}
	select {
	case <-disconnected:
	case <-time.After(3 * time.Second):
		t.Fatal("connection authenticated with a revoked key stayed open")
	}
	if srv.ActiveConnectionCount() != 0 {
		t.Fatalf("ActiveConnectionCount() = %d, want 0", srv.ActiveConnectionCount())
	}
}

// A channel to a non-loopback destination is refused before any handoff.
func TestAPIChannelRequiresLoopbackDestination(t *testing.T) {
	srv, tmpDir := testServer(t)
	set := newEnrolledSet()
	srv.SetProductHooks(set.hooks())
	handed := false
	srv.SetAPIHandoff(func(conn *APIConn) error { handed = true; _ = conn.Close(); return nil })
	host, port, known := startServer(t, srv, tmpDir)
	client, _ := connectEnrolledClient(t, srv, set, tmpDir, host, port, known)
	client.mu.Lock()
	sshClient := client.sshClient
	client.mu.Unlock()
	if _, err := sshClient.Dial("tcp", net.JoinHostPort("10.0.0.1", "80")); err == nil {
		t.Fatal("non-loopback destination was accepted")
	}
	if handed {
		t.Fatal("non-loopback channel reached the handoff")
	}
}

// chanListener serves the handed-off API connections to an http.Server.
type chanListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newChanListener() *chanListener {
	return &chanListener{conns: make(chan net.Conn, 8), done: make(chan struct{})}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

// A client that drops its connection mid-request cancels the request on the
// HTTP side and frees the channel handler at once, rather than leaving both
// waiting for a response that will never be read.
func TestAPIChannelCloseCancelsHTTPRequest(t *testing.T) {
	srv, tmpDir := testServer(t)
	set := newEnrolledSet()
	srv.SetProductHooks(set.hooks())

	ln := newChanListener()
	started := make(chan struct{})
	canceled := make(chan struct{})
	httpSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(canceled)
	})}
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() { _ = httpSrv.Close() })
	srv.SetAPIHandoff(func(conn *APIConn) error {
		ln.conns <- conn
		return nil
	})
	host, port, known := startServer(t, srv, tmpDir)
	client, _ := connectEnrolledClient(t, srv, set, tmpDir, host, port, known)

	conn, err := client.DialSignerAPI(context.Background())
	if err != nil {
		t.Fatalf("DialSignerAPI() error = %v", err)
	}
	if _, err := conn.Write([]byte("GET /slow HTTP/1.1\r\nHost: signer\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not reach the HTTP handler")
	}
	_ = conn.Close()
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("closing the channel did not cancel the HTTP request")
	}

	// With the channel torn down, the client's connection is the only
	// handler Stop has to wait for; it must not be stuck on the channel.
	_ = client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.StopContext(ctx); err != nil {
		t.Fatalf("StopContext() error = %v, want prompt shutdown", err)
	}
}

// When the HTTP side closes the connection, the client sees EOF and the
// channel is closed without waiting for the client to act.
func TestAPIChannelHTTPCloseEndsChannel(t *testing.T) {
	srv, tmpDir := testServer(t)
	set := newEnrolledSet()
	srv.SetProductHooks(set.hooks())
	srv.SetAPIHandoff(func(conn *APIConn) error {
		go func() {
			_, _ = conn.Write([]byte("bye\n"))
			_ = conn.Close()
		}()
		return nil
	})
	host, port, known := startServer(t, srv, tmpDir)
	client, _ := connectEnrolledClient(t, srv, set, tmpDir, host, port, known)

	conn, err := client.DialSignerAPI(context.Background())
	if err != nil {
		t.Fatalf("DialSignerAPI() error = %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	data, err := io.ReadAll(conn)
	if string(data) != "bye\n" || err != nil {
		t.Fatalf("ReadAll() = %q, %v, want the response then EOF", data, err)
	}
}
