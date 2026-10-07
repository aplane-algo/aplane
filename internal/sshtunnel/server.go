// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// productSSHUsername is the fixed, non-secret username for enrolled client
	// connections.
	productSSHUsername = "aplane"
	// enrollmentSSHUsername is the username of a bootstrap connection that
	// asks the operator to enroll the client's key. It carries no credential
	// and may open only the enrollment session.
	enrollmentSSHUsername = "request-enrollment"
	// enrollmentCommand is the one exec command an enrollment connection may
	// run. An optional label follows it, separated by a space.
	enrollmentCommand = "enroll"
	// maxEnrollmentLabelBytes bounds the client-supplied display label.
	maxEnrollmentLabelBytes = 64
	// RevokedRequestType is the global request the server sends before it
	// closes a connection whose key was revoked, so the client can report why.
	RevokedRequestType = "key-revoked@aplane"
)

// isClosedConnError returns true if the error is due to use of a closed connection
// These are expected during normal disconnects and shouldn't be logged as errors
func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	// Check for common closed connection error patterns
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "broken pipe")
}

// SessionCallback is called when SSH sessions connect or disconnect
type SessionCallback func(remoteAddr string, connected bool)

// EnrollmentApprovalCallback asks the operator to approve enrolling the key
// with the given fingerprint. It is canceled when the SSH client disconnects.
type EnrollmentApprovalCallback func(ctx context.Context, sshFingerprint, label, remoteAddr string) (approved bool, err error)

// EnrollmentAuditCallback is called after the enrollment acknowledgement has
// been delivered to the client.
type EnrollmentAuditCallback func(sshFingerprint, label, remoteAddr string)

// OperatorCheckCallback is called to check if the product operator is connected.
type OperatorCheckCallback func() bool

// KeyCheckerFunc reports whether a public key is currently enrolled.
type KeyCheckerFunc func(key ssh.PublicKey) bool

// KeyEnrollerFunc enrolls a public key with a display label. It must be
// idempotent for an already-enrolled key.
type KeyEnrollerFunc func(key ssh.PublicKey, label string) error

// ProductHooks connects the server to the product's enrolled-key registry.
// Both hooks are required together; without them the server keeps an
// in-memory key list that exists for tests.
type ProductHooks struct {
	CheckKey  KeyCheckerFunc
	EnrollKey KeyEnrollerFunc
}

// EnrollmentHooks configures the operator-approved request-enrollment flow.
// The server enrolls the key only after approval and audits only after the
// acknowledgement reached the client.
type EnrollmentHooks struct {
	ApproveContext    EnrollmentApprovalCallback
	AuditEnrolled     EnrollmentAuditCallback
	OperatorConnected OperatorCheckCallback
}

// APIHandoff receives each accepted API channel as a connection carrying the
// authenticated client's identity. It returns an error to refuse the channel,
// for example when the receiving listener is full or closed.
type APIHandoff func(conn *APIConn) error

// APIConn is one forwarded API connection. The HTTP server reads the client
// identity from it through its connection context.
type APIConn struct {
	net.Conn
	fingerprint string
	remote      net.Addr
	local       net.Addr
}

// KeyFingerprint is the SHA256 fingerprint of the enrolled key that opened
// the channel.
func (c *APIConn) KeyFingerprint() string { return c.fingerprint }

// RemoteAddr is the SSH peer's address, not a loopback socket.
func (c *APIConn) RemoteAddr() net.Addr { return c.remote }

// LocalAddr is the SSH listener's address.
func (c *APIConn) LocalAddr() net.Addr { return c.local }

const (
	initialAcceptErrorBackoff = 25 * time.Millisecond
	maxAcceptErrorBackoff     = time.Second
	sshHandshakeTimeout       = 60 * time.Second
	maxPendingSSHHandshakes   = 64
	// One remote address may hold only a share of the handshake slots, so a
	// single host cannot keep every slot busy for the handshake timeout.
	maxPendingSSHHandshakesPerHost = 8

	// request-enrollment connections are unauthenticated, so their footprint
	// is bounded: a few concurrent connections, each of which must start
	// enrollment promptly and may request it only once.
	maxEnrollmentConns         = 8
	maxEnrollmentChannels      = 2
	enrollmentExecDeadline     = 30 * time.Second
	enrollmentResponseDeadline = 10 * time.Second
	maxLoggedClientTextBytes   = 64

	// The server pings each client and closes a connection whose client
	// stops answering. The library cannot cancel a pending request, so the
	// reply is awaited with a timer rather than indefinitely.
	keepaliveInterval     = 15 * time.Second
	keepaliveReplyTimeout = 30 * time.Second
)

// Server is the node's SSH server. An enrolled key authenticates a client;
// the client's API channels are handed to the HTTP server in-process with
// that identity attached. A bootstrap username lets an unknown key ask the
// operator for enrollment.
type Server struct {
	listenAddr      string          // Address to listen on (e.g., "127.0.0.1:2222")
	sessionCallback SessionCallback // Optional callback for session events

	sshConfig *ssh.ServerConfig
	listener  net.Listener
	hostKey   ssh.Signer

	// In-memory enrolled keys, used only when no product hooks are set.
	authKeys   []ssh.PublicKey
	authKeysMu sync.RWMutex

	// Product registry hooks
	keyChecker  KeyCheckerFunc
	keyEnroller KeyEnrollerFunc

	// API channel handoff; nil refuses every API channel.
	apiHandoff APIHandoff

	// Enrollment callbacks
	enrollmentApprovalCallback EnrollmentApprovalCallback
	enrollmentAuditCallback    EnrollmentAuditCallback
	operatorCheckCallback      OperatorCheckCallback

	mu        sync.Mutex
	started   bool
	running   bool
	closeChan chan struct{}

	// Connection tracking for graceful shutdown
	activeConns              sync.WaitGroup                  // Tracks active connection handlers
	sshConns                 map[*ssh.ServerConn]sshConnInfo // Active SSH connections for explicit close
	rawConns                 map[net.Conn]struct{}           // Sockets not yet tracked as active SSH connections; protected by sshConnsMu.
	pendingHandshakes        int
	pendingHandshakesByHost  map[string]int // Pending handshakes per remote IP; protected by sshConnsMu
	handshakeTimeout         time.Duration
	sshConnsMu               sync.Mutex // Protects connection maps and pendingHandshakes
	testAfterAuthBeforeTrack func()     // Test hook for auth/revocation race coverage

	enrollmentConns        int           // Live request-enrollment connections; protected by sshConnsMu
	enrollmentExecDeadline time.Duration // Tests may shorten the time an enrollment connection has to start
	enrollmentRespDeadline time.Duration // Tests may shorten the time a client has to accept an enrollment response
	keepaliveInterval      time.Duration // Tests may shorten keepaliveInterval
	keepaliveTimeout       time.Duration // Tests may shorten keepaliveReplyTimeout
	enrollmentClaims       sync.Map      // *ssh.ServerConn -> struct{}: connections that already requested enrollment
	enrollmentActive       atomic.Bool   // One enrollment request is pending at a time, server-wide
}

// sshConnInfo is what the server remembers about an authenticated connection.
type sshConnInfo struct {
	fingerprint string
	key         ssh.PublicKey // nil for enrollment connections
}

// SetSessionCallback sets a callback for session connect/disconnect events.
// Callbacks are immutable after Start.
func (s *Server) SetSessionCallback(cb SessionCallback) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assertNotStartedLocked("SetSessionCallback")
	s.sessionCallback = cb
}

// SetEnrollmentHooks configures the request-enrollment flow. Hooks are
// immutable after Start.
func (s *Server) SetEnrollmentHooks(hooks EnrollmentHooks) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assertNotStartedLocked("SetEnrollmentHooks")
	s.enrollmentApprovalCallback = hooks.ApproveContext
	s.enrollmentAuditCallback = hooks.AuditEnrolled
	s.operatorCheckCallback = hooks.OperatorConnected
}

// SetAPIHandoff installs the receiver of forwarded API channels. It is
// immutable after Start. Without it every API channel is refused.
func (s *Server) SetAPIHandoff(handoff APIHandoff) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assertNotStartedLocked("SetAPIHandoff")
	s.apiHandoff = handoff
}

// CloseConnectionsForFingerprint closes every connection authenticated with
// the key that has the given fingerprint, telling the client why first. The
// caller installs the new registry view before calling this, and the
// post-handshake re-check (see handleConnection) closes the auth-before-track
// race, so a revoked key cannot keep or regain a connection.
func (s *Server) CloseConnectionsForFingerprint(fingerprint, reason string) int {
	s.sshConnsMu.Lock()
	conns := make([]*ssh.ServerConn, 0)
	for conn, info := range s.sshConns {
		if info.fingerprint == fingerprint {
			conns = append(conns, conn)
		}
	}
	s.sshConnsMu.Unlock()
	s.closeRevoked(conns, reason)
	return len(conns)
}

// CloseAllClientConnections closes every authenticated connection, enrolled
// and enrollment alike, telling clients why first.
func (s *Server) CloseAllClientConnections(reason string) int {
	s.sshConnsMu.Lock()
	conns := make([]*ssh.ServerConn, 0, len(s.sshConns))
	for conn := range s.sshConns {
		conns = append(conns, conn)
	}
	s.sshConnsMu.Unlock()
	s.closeRevoked(conns, reason)
	return len(conns)
}

func (s *Server) closeRevoked(conns []*ssh.ServerConn, reason string) {
	payload := []byte(reason)
	for _, conn := range conns {
		_, _, _ = conn.SendRequest(RevokedRequestType, false, payload)
		_ = conn.Close()
	}
}

// ConnectedFingerprints returns the number of live connections per enrolled
// key fingerprint. Enrollment connections are not counted.
func (s *Server) ConnectedFingerprints() map[string]int {
	s.sshConnsMu.Lock()
	defer s.sshConnsMu.Unlock()
	counts := make(map[string]int)
	for _, info := range s.sshConns {
		if info.key != nil {
			counts[info.fingerprint]++
		}
	}
	return counts
}

// ActiveConnectionCount returns the number of active SSH client connections.
func (s *Server) ActiveConnectionCount() int {
	s.sshConnsMu.Lock()
	n := len(s.sshConns)
	s.sshConnsMu.Unlock()
	return n
}

// SetProductHooks connects the server to the product's enrolled-key registry.
// Hooks are immutable after Start.
func (s *Server) SetProductHooks(hooks ProductHooks) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assertNotStartedLocked("SetProductHooks")
	if (hooks.CheckKey == nil) != (hooks.EnrollKey == nil) {
		panic("product SSH hooks require CheckKey and EnrollKey together")
	}
	s.keyChecker = hooks.CheckKey
	s.keyEnroller = hooks.EnrollKey
}

// isEnrolled reports whether key is currently enrolled, through the product
// registry when hooks are set and the in-memory list otherwise.
func (s *Server) isEnrolled(key ssh.PublicKey) bool {
	if s.keyChecker != nil {
		return s.keyChecker(key)
	}
	return s.hasAuthorizedKey(key)
}

func (s *Server) assertNotStartedLocked(method string) {
	if s.started {
		panic(fmt.Sprintf("sshtunnel.Server.%s cannot be called after Start", method))
	}
}

// NewServer creates an SSH server that authenticates clients by enrolled
// public key. The host key at hostKeyPath is loaded, or generated if absent.
func NewServer(listenAddr, hostKeyPath string) (*Server, error) {
	hostKey, err := loadOrGenerateHostKey(hostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load host key: %w", err)
	}

	server := &Server{
		listenAddr:              listenAddr,
		hostKey:                 hostKey,
		closeChan:               make(chan struct{}),
		sshConns:                make(map[*ssh.ServerConn]sshConnInfo),
		rawConns:                make(map[net.Conn]struct{}),
		pendingHandshakesByHost: make(map[string]int),
		handshakeTimeout:        sshHandshakeTimeout,

		enrollmentExecDeadline: enrollmentExecDeadline,
		enrollmentRespDeadline: enrollmentResponseDeadline,
		keepaliveInterval:      keepaliveInterval,
		keepaliveTimeout:       keepaliveReplyTimeout,
	}

	server.sshConfig = &ssh.ServerConfig{
		PublicKeyAuthAlgorithms: clientKeyAlgorithms,
		PublicKeyCallback:       server.handlePublicKeyAuth,
		AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
			fmt.Println(formatSSHAuthLog(conn, method, err))
		},
		ServerVersion: "SSH-2.0-APlane",
	}
	server.sshConfig.AddHostKey(hostKey)

	return server, nil
}

func formatSSHAuthLog(conn ssh.ConnMetadata, method string, err error) string {
	outcome := "accepted"
	if err != nil {
		outcome = "rejected"
	}
	return fmt.Sprintf("[SSH] Authentication from %s: method=%s outcome=%s", conn.RemoteAddr(), method, outcome)
}

// loadOrGenerateHostKey loads a host key from disk or generates and stores a new one.
func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	if path == "" {
		return nil, fmt.Errorf("host key path is empty")
	}

	data, err := os.ReadFile(path)
	if err == nil {
		if info, statErr := os.Stat(path); statErr == nil {
			if info.Mode().Perm()&0077 != 0 {
				return nil, fmt.Errorf("host key %s has insecure permissions %04o (expected 0600)", path, info.Mode().Perm())
			}
		}
		signer, parseErr := ssh.ParsePrivateKey(data)
		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse host key %s: %w", path, parseErr)
		}
		return signer, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read host key %s: %w", path, err)
	}

	// Generate Ed25519 key and persist it
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		return nil, fmt.Errorf("failed to encode host key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create host key directory %s: %w", dir, err)
		}
	}

	if err := writeNewPrivateKeyFile(path, pemBytes); err != nil {
		return nil, fmt.Errorf("failed to write host key %s: %w", path, err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	return signer, nil
}

func writeNewPrivateKeyFile(path string, pemBytes []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(pemBytes); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return nil
}

// handlePublicKeyAuth decides key eligibility; SSH then verifies possession,
// and the permissions returned here are installed only after that signature
// check succeeds. For the product username the key must be enrolled now,
// and it is checked again after the handshake (see handleConnection) so a
// revocation during authentication still refuses the connection. For the
// enrollment username any acceptable key may proceed to ask the operator.
func (s *Server) handlePublicKeyAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	remoteAddr := conn.RemoteAddr().String()
	keyFingerprint := ssh.FingerprintSHA256(key)
	username := conn.User()

	if username == enrollmentSSHUsername {
		return s.handleEnrollmentAuth(key, remoteAddr, keyFingerprint)
	}
	if username != productSSHUsername {
		return nil, fmt.Errorf("unsupported SSH username: only %q is accepted", productSSHUsername)
	}
	if !s.isEnrolled(key) {
		fmt.Printf("[SSH] Rejected unknown key from %s: %s\n", remoteAddr, keyFingerprint)
		return nil, fmt.Errorf("unknown key %s; use request-enrollment to enroll", keyFingerprint)
	}
	return &ssh.Permissions{Extensions: map[string]string{
		"auth_method":     "publickey",
		"key_fingerprint": keyFingerprint,
		"public_key":      string(ssh.MarshalAuthorizedKey(key)),
	}}, nil
}

// handleEnrollmentAuth admits a bootstrap connection. Only key possession is
// proven; the connection may open nothing but the enrollment session, and
// the operator decides whether the key is enrolled.
func (s *Server) handleEnrollmentAuth(key ssh.PublicKey, remoteAddr, keyFingerprint string) (*ssh.Permissions, error) {
	// clientKeyAlgorithms has already refused other key types before
	// verification; this keeps enrollment to the same set.
	if err := checkEnrollmentKey(key); err != nil {
		fmt.Printf("[SSH] Enrollment key from %s refused (key: %s): %v\n", remoteAddr, keyFingerprint, err)
		return nil, err
	}
	fmt.Printf("[SSH] Enrollment request from %s (key: %s)\n", remoteAddr, keyFingerprint)
	return &ssh.Permissions{
		Extensions: map[string]string{
			"auth_method":     "enrollment",
			"key_fingerprint": keyFingerprint,
			"public_key":      string(ssh.MarshalAuthorizedKey(key)),
		},
	}, nil
}

// enrollKey enrolls a public key through the product registry when hooks are
// set, and into the in-memory list otherwise.
func (s *Server) enrollKey(key ssh.PublicKey, label string) error {
	if s.keyEnroller != nil {
		return s.keyEnroller(key, label)
	}
	s.authKeysMu.Lock()
	defer s.authKeysMu.Unlock()
	if !authorizedKeyInList(s.authKeys, key) {
		s.authKeys = append(s.authKeys, key)
	}
	return nil
}

func (s *Server) hasAuthorizedKey(key ssh.PublicKey) bool {
	s.authKeysMu.RLock()
	defer s.authKeysMu.RUnlock()
	return authorizedKeyInList(s.authKeys, key)
}

func authorizedKeyInList(keys []ssh.PublicKey, key ssh.PublicKey) bool {
	for _, allowedKey := range keys {
		if bytes.Equal(allowedKey.Marshal(), key.Marshal()) {
			return true
		}
	}
	return false
}

// Start begins listening for SSH connections
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("server already started")
	}
	s.started = true
	s.mu.Unlock()

	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		s.mu.Lock()
		s.started = false
		s.mu.Unlock()
		return fmt.Errorf("failed to listen on %s: %w", s.listenAddr, err)
	}

	s.mu.Lock()
	s.listener = listener
	s.running = true
	s.mu.Unlock()

	fmt.Printf("SSH server listening on %s\n", s.listenAddr)

	// Accept connections in background
	s.activeConns.Add(1)
	go func() {
		defer s.activeConns.Done()
		s.acceptConnections(ctx, listener)
	}()

	return nil
}

// acceptConnections handles incoming SSH connections
func (s *Server) acceptConnections(ctx context.Context, listener net.Listener) {
	backoff := initialAcceptErrorBackoff
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.closeChan:
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-s.closeChan:
				return
			case <-time.After(backoff):
			}
			backoff = nextAcceptErrorBackoff(backoff)
			continue
		}
		backoff = initialAcceptErrorBackoff

		// Admit before spawning a handler so stalled peers cannot create
		// an unbounded number of authentication goroutines.
		if !s.admitConnection(conn) {
			_ = conn.Close()
			continue
		}
		s.activeConns.Add(1)
		go s.handleConnection(conn)
	}
}

func nextAcceptErrorBackoff(current time.Duration) time.Duration {
	if current <= 0 {
		return initialAcceptErrorBackoff
	}
	next := current * 2
	if next > maxAcceptErrorBackoff {
		return maxAcceptErrorBackoff
	}
	return next
}

// admitConnection also serializes admission with shutdown's socket snapshot.
func (s *Server) admitConnection(conn net.Conn) bool {
	s.sshConnsMu.Lock()
	defer s.sshConnsMu.Unlock()
	select {
	case <-s.closeChan:
		return false
	default:
	}
	if s.pendingHandshakes >= maxPendingSSHHandshakes {
		return false
	}
	host := remoteHost(conn)
	if s.pendingHandshakesByHost[host] >= maxPendingSSHHandshakesPerHost {
		return false
	}
	s.rawConns[conn] = struct{}{}
	s.pendingHandshakes++
	s.pendingHandshakesByHost[host]++
	return true
}

// finishPendingHandshakeLocked releases conn's handshake slot. The caller
// holds sshConnsMu.
func (s *Server) finishPendingHandshakeLocked(conn net.Conn) {
	s.pendingHandshakes--
	host := remoteHost(conn)
	if s.pendingHandshakesByHost[host] <= 1 {
		delete(s.pendingHandshakesByHost, host)
	} else {
		s.pendingHandshakesByHost[host]--
	}
}

// remoteHost is the IP a connection came from, without its port.
func remoteHost(conn net.Conn) string {
	addr := conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// handleConnection processes a single SSH connection
func (s *Server) handleConnection(netConn net.Conn) {
	defer s.activeConns.Done() // Signal handler completion (runs last due to LIFO)

	defer func() {
		if err := netConn.Close(); err != nil && !isClosedConnError(err) {
			fmt.Printf("Failed to close network connection: %v\n", err)
		}
	}()

	// Some internal callers invoke the handler directly.
	s.sshConnsMu.Lock()
	_, admitted := s.rawConns[netConn]
	s.sshConnsMu.Unlock()
	if !admitted && !s.admitConnection(netConn) {
		return
	}
	pending := true
	defer func() {
		s.sshConnsMu.Lock()
		delete(s.rawConns, netConn)
		if pending {
			s.finishPendingHandshakeLocked(netConn)
		}
		s.sshConnsMu.Unlock()
	}()
	if err := netConn.SetDeadline(time.Now().Add(s.handshakeTimeout)); err != nil {
		return
	}
	sshConn, chans, reqs, err := ssh.NewServerConn(netConn, s.sshConfig)
	if err != nil {
		return
	}
	if err := netConn.SetDeadline(time.Time{}); err != nil {
		return
	}
	s.sshConnsMu.Lock()
	s.finishPendingHandshakeLocked(netConn)
	pending = false
	s.sshConnsMu.Unlock()
	if s.testAfterAuthBeforeTrack != nil {
		s.testAfterAuthBeforeTrack()
	}

	info := sshConnInfo{}
	isEnrollment := false
	if sshConn.Permissions != nil {
		info.fingerprint = sshConn.Permissions.Extensions["key_fingerprint"]
		switch sshConn.Permissions.Extensions["auth_method"] {
		case "publickey":
			if key, _, _, _, parseErr := ssh.ParseAuthorizedKey([]byte(sshConn.Permissions.Extensions["public_key"])); parseErr == nil {
				info.key = key
			}
		case "enrollment":
			isEnrollment = true
		}
	}

	// Track the connection for shutdown and revocation. The enrollment check
	// is repeated here, under the same lock revocation uses to find
	// connections, so a key revoked while its handshake was in flight is
	// refused rather than registered after the revocation's close pass.
	s.sshConnsMu.Lock()
	revoked := !isEnrollment && (info.key == nil || !s.isEnrolled(info.key))
	if !revoked {
		s.sshConns[sshConn] = info
	}
	delete(s.rawConns, netConn)
	s.sshConnsMu.Unlock()

	remoteAddr := sshConn.RemoteAddr().String()

	// Channel to signal keepalive monitor to stop
	keepaliveDone := make(chan struct{})
	connectedLogged := false

	defer func() {
		// Stop keepalive monitor
		close(keepaliveDone)

		// Unregister connection
		s.sshConnsMu.Lock()
		delete(s.sshConns, sshConn)
		s.sshConnsMu.Unlock()

		if err := sshConn.Close(); err != nil && !isClosedConnError(err) {
			fmt.Printf("Failed to close SSH connection: %v\n", err)
		}
		// Log the session disconnect.
		fmt.Printf("[SSH] Client disconnected: %s\n", remoteAddr)
		if connectedLogged && s.sessionCallback != nil {
			s.sessionCallback(remoteAddr, false)
		}
	}()

	if revoked {
		_, _, _ = sshConn.SendRequest(RevokedRequestType, false, []byte("key revoked"))
		return
	}

	// Log the successful SSH connection.
	fmt.Printf("[SSH] Client connected from %s\n", remoteAddr)
	if s.sessionCallback != nil {
		s.sessionCallback(remoteAddr, true)
	}
	connectedLogged = true

	// Handle global requests (including keepalives from client).
	// Every per-connection goroutine joins activeConns so Stop's wait covers
	// them; otherwise channel handlers could outlive shutdown into the
	// daemon's key-zeroing teardown. The Adds happen while this handler's own
	// activeConns slot is held, so they cannot race a concurrent Wait.
	s.activeConns.Add(1)
	go func() {
		defer s.activeConns.Done()
		s.handleGlobalRequests(reqs)
	}()

	// Start server-side keepalive monitor to detect dead clients
	s.activeConns.Add(1)
	go func() {
		defer s.activeConns.Done()
		s.monitorClientConnection(sshConn, remoteAddr, keepaliveDone)
	}()

	connCtx, cancelConnCtx := context.WithCancel(context.Background())
	defer cancelConnCtx()

	if isEnrollment {
		if !s.admitEnrollmentConn() {
			fmt.Printf("[SSH] Too many pending enrollment requests; closing %s\n", remoteAddr)
			return
		}
		defer s.releaseEnrollmentConn(sshConn)
		// An enrollment connection that has not started by the deadline is
		// closed, so idle unauthenticated connections cannot pile up.
		deadline := time.AfterFunc(s.enrollmentExecDeadline, func() {
			if _, claimed := s.enrollmentClaims.Load(sshConn); !claimed {
				_ = sshConn.Close()
			}
		})
		defer deadline.Stop()
	}

	// Handle channel requests
	var enrollmentChannels atomic.Int32
	for newChannel := range chans {
		if isEnrollment {
			// Enrollment mode: handle session channels for exec. The
			// connection is unauthenticated, so its open channels are capped
			// before any is accepted.
			if enrollmentChannels.Load() >= maxEnrollmentChannels {
				if err := newChannel.Reject(ssh.ResourceShortage, "too many channels for enrollment"); err != nil && !isClosedConnError(err) {
					fmt.Printf("Failed to reject SSH channel: %v\n", err)
				}
				continue
			}
			enrollmentChannels.Add(1)
			s.activeConns.Add(1)
			go func(ch ssh.NewChannel) {
				defer s.activeConns.Done()
				defer enrollmentChannels.Add(-1)
				s.handleEnrollmentChannel(connCtx, sshConn, ch)
			}(newChannel)
			continue
		}

		switch newChannel.ChannelType() {
		case "direct-tcpip":
			s.activeConns.Add(1)
			go func(ch ssh.NewChannel) {
				defer s.activeConns.Done()
				s.handleChannel(sshConn, info, ch)
			}(newChannel)
		default:
			if err := newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type"); err != nil && !isClosedConnError(err) {
				fmt.Printf("Failed to reject SSH channel: %v\n", err)
			}
		}
	}
}

// handleGlobalRequests handles global SSH requests including keepalives.
// This replaces ssh.DiscardRequests to properly respond to keepalive pings.
func (s *Server) handleGlobalRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "keepalive@openssh.com":
			// Respond to keepalive from client
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		default:
			// Reject unknown requests
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// monitorClientConnection sends keepalive pings to detect dead clients.
// This ensures the server detects when a client's network dies (laptop closes,
// cable pulled, etc.) rather than waiting for TCP timeout.
func (s *Server) monitorClientConnection(sshConn *ssh.ServerConn, remoteAddr string, done chan struct{}) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[SSH] Keepalive goroutine panic for %s: %v\n", remoteAddr, r)
			_ = sshConn.Close()
		}
	}()

	ticker := time.NewTicker(s.keepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			// SendRequest waits for the reply until the connection closes, so
			// it runs aside and the reply is awaited under a timer. Closing
			// the connection unblocks it.
			replied := make(chan error, 1)
			go func() {
				_, _, err := sshConn.SendRequest("keepalive@openssh.com", true, nil)
				replied <- err
			}()
			select {
			case err := <-replied:
				if err != nil {
					fmt.Printf("[SSH] Keepalive failed for %s: %v\n", remoteAddr, err)
					_ = sshConn.Close()
					return
				}
			case <-time.After(s.keepaliveTimeout):
				fmt.Printf("[SSH] No keepalive reply from %s within %v; closing\n", remoteAddr, s.keepaliveTimeout)
				_ = sshConn.Close()
				return
			case <-done:
				return
			}
		}
	}
}

// handleEnrollmentChannel handles the session channel of an enrollment
// connection. Only an "exec" request running "enroll [<label>]" is accepted.
func (s *Server) handleEnrollmentChannel(connCtx context.Context, sshConn *ssh.ServerConn, newChannel ssh.NewChannel) {
	if newChannel.ChannelType() != "session" {
		if err := newChannel.Reject(ssh.UnknownChannelType, "only session channels are supported for enrollment"); err != nil {
			fmt.Printf("Failed to reject channel: %v\n", err)
		}
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	// claimed is set once this channel takes the connection's single
	// enrollment request; the connection then closes when the request
	// finishes, whatever the outcome, so a refused or rejected client cannot
	// keep holding one of the few enrollment connection slots.
	claimed := false
	defer func() {
		if err := channel.Close(); err != nil && !isClosedConnError(err) {
			fmt.Printf("Failed to close enrollment channel: %v\n", err)
		}
		if claimed {
			_ = sshConn.Close()
		}
	}()
	approvalCtx, cancelApproval := context.WithCancel(connCtx)
	defer cancelApproval()

	fingerprint := ""
	if sshConn.Permissions != nil && sshConn.Permissions.Extensions != nil {
		fingerprint = sshConn.Permissions.Extensions["key_fingerprint"]
	}
	remoteAddr := sshConn.RemoteAddr().String()

	for req := range requests {
		switch req.Type {
		case "exec":
			command, ok := parseExecCommand(req.Payload)
			if !ok {
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				continue
			}
			label, ok := parseEnrollmentCommand(command)
			if !ok {
				fmt.Printf("[SSH] Unknown enrollment command from %s: %s\n", remoteAddr, quoteClientText(command))
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				_, _ = channel.Write([]byte("ERROR: unknown command\n"))
				continue
			}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			go cancelOnEnrollmentChannelClosed(requests, cancelApproval)
			claimed = s.requestEnrollment(approvalCtx, sshConn, channel, fingerprint, label, remoteAddr)
			return

		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// parseEnrollmentCommand accepts "enroll" or "enroll <label>" and returns the
// label. A label is bounded, printable, and single-line; anything else is
// not an enrollment command.
func parseEnrollmentCommand(command string) (label string, ok bool) {
	if command == enrollmentCommand {
		return "", true
	}
	rest, found := strings.CutPrefix(command, enrollmentCommand+" ")
	if !found {
		return "", false
	}
	rest = strings.TrimSpace(rest)
	if rest == "" || len(rest) > maxEnrollmentLabelBytes {
		return "", false
	}
	for _, r := range rest {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return rest, true
}

// requestEnrollment runs the connection's single enrollment request. It
// reports whether the request claimed the connection, which then closes when
// the request ends.
func (s *Server) requestEnrollment(ctx context.Context, sshConn *ssh.ServerConn, channel ssh.Channel, fingerprint, label, remoteAddr string) bool {
	if s.operatorCheckCallback == nil || !s.operatorCheckCallback() {
		fmt.Printf("[SSH] Enrollment rejected from %s: no operator connected\n", remoteAddr)
		_, _ = channel.Write([]byte("no operator (apadmin) connected to approve the enrollment request\n"))
		_ = s.sendExitStatus(channel, 1)
		return false
	}
	if s.enrollmentApprovalCallback == nil {
		_, _ = channel.Write([]byte("enrollment is not configured on this server\n"))
		_ = s.sendExitStatus(channel, 1)
		return false
	}

	// One enrollment request per connection, and one pending request
	// server-wide: an unauthenticated client cannot queue a stream of
	// operator prompts.
	if _, already := s.enrollmentClaims.LoadOrStore(sshConn, struct{}{}); already {
		_ = s.respondEnrollment(sshConn, channel, "ERROR: only one enrollment request is allowed per connection\n", 1)
		return false
	}
	if !s.enrollmentActive.CompareAndSwap(false, true) {
		fmt.Printf("[SSH] Enrollment request from %s refused: another request is pending\n", remoteAddr)
		_ = s.respondEnrollment(sshConn, channel, "ERROR: another enrollment request is pending; try again later\n", 1)
		return true
	}
	defer s.enrollmentActive.Store(false)

	s.approveAndEnroll(ctx, sshConn, channel, fingerprint, label, remoteAddr)
	return true
}

// approveAndEnroll asks the operator to approve the key, enrolls it, and
// acknowledges. Each step runs only after the previous one succeeds. The
// enrollment is audited as soon as the registry holds the key, since that is
// when the key becomes usable; a lost acknowledgement does not undo it. No
// credential is issued: the client's key is its credential.
func (s *Server) approveAndEnroll(ctx context.Context, sshConn *ssh.ServerConn, channel ssh.Channel, fingerprint, label, remoteAddr string) {
	fmt.Printf("[SSH] Waiting for operator approval in apadmin for enrollment request from %s\n", remoteAddr)

	approved, err := s.enrollmentApprovalCallback(ctx, fingerprint, label, remoteAddr)
	if err != nil {
		_ = s.respondEnrollment(sshConn, channel, fmt.Sprintf("ERROR: %s\n", err.Error()), 1)
		return
	}
	if !approved {
		_ = s.respondEnrollment(sshConn, channel, "ERROR: enrollment rejected by operator\n", 1)
		return
	}

	key, ok := enrollmentPublicKey(sshConn.Permissions)
	if !ok {
		_ = s.respondEnrollment(sshConn, channel, "ERROR: failed to enroll SSH key\n", 1)
		return
	}
	if err := s.enrollKey(key, label); err != nil {
		fmt.Printf("[SSH] Failed to enroll SSH key: %v\n", err)
		_ = s.respondEnrollment(sshConn, channel, "ERROR: failed to enroll SSH key\n", 1)
		return
	}
	// The registry changed: the key is enrolled and usable from here on,
	// whether or not the client learns of it, so the audit event records
	// the authority change itself. Acknowledgement delivery is logged
	// separately below.
	if s.enrollmentAuditCallback != nil {
		s.enrollmentAuditCallback(fingerprint, label, remoteAddr)
	}
	fmt.Printf("[SSH] SSH key enrolled for %s (key: %s)\n", remoteAddr, fingerprint)

	if ctx.Err() != nil {
		fmt.Printf("[SSH] Enrollment client %s disconnected before acknowledgement; its key stays enrolled: %v\n", remoteAddr, ctx.Err())
		return
	}
	if err := s.respondEnrollment(sshConn, channel, "enrolled "+fingerprint+"\n", 0); err != nil {
		fmt.Printf("[SSH] Failed to acknowledge enrollment to %s; its key stays enrolled: %v\n", remoteAddr, err)
		return
	}
}

// enrollmentPublicKey returns the key the enrollment connection authenticated
// with, as recorded by handleEnrollmentAuth.
func enrollmentPublicKey(permissions *ssh.Permissions) (ssh.PublicKey, bool) {
	if permissions == nil || permissions.Extensions == nil {
		return nil, false
	}
	text := permissions.Extensions["public_key"]
	if text == "" {
		return nil, false
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(text))
	if err != nil {
		return nil, false
	}
	return key, true
}

// admitEnrollmentConn counts a live request-enrollment connection, refusing
// one beyond the cap.
func (s *Server) admitEnrollmentConn() bool {
	s.sshConnsMu.Lock()
	defer s.sshConnsMu.Unlock()
	if s.enrollmentConns >= maxEnrollmentConns {
		return false
	}
	s.enrollmentConns++
	return true
}

func (s *Server) releaseEnrollmentConn(sshConn *ssh.ServerConn) {
	s.sshConnsMu.Lock()
	s.enrollmentConns--
	s.sshConnsMu.Unlock()
	s.enrollmentClaims.Delete(sshConn)
}

// respondEnrollment writes an enrollment result and exit status under a
// deadline. A client that stops reading, for example by advertising a zero
// receive window, would otherwise block the write and hold the server-wide
// enrollment slot; at the deadline its connection is closed, which fails the
// write and lets the handler release the slot.
func (s *Server) respondEnrollment(sshConn ssh.Conn, channel ssh.Channel, msg string, status uint32) error {
	deadline := time.AfterFunc(s.enrollmentRespDeadline, func() { _ = sshConn.Close() })
	defer deadline.Stop()
	if _, err := channel.Write([]byte(msg)); err != nil {
		return err
	}
	return s.sendExitStatus(channel, status)
}

// quoteClientText renders unauthenticated client text for a log line: quoted
// so control characters and terminal escapes print as escapes, and truncated.
func quoteClientText(text string) string {
	if len(text) > maxLoggedClientTextBytes {
		return strconv.Quote(text[:maxLoggedClientTextBytes]) + "..."
	}
	return strconv.Quote(text)
}

func parseExecCommand(payload []byte) (string, bool) {
	if len(payload) < 4 {
		return "", false
	}
	cmdLen := binary.BigEndian.Uint32(payload[:4])
	if cmdLen > uint32(len(payload)-4) {
		return "", false
	}
	cmdLenInt := int(cmdLen)
	return string(payload[4 : 4+cmdLenInt]), true
}

func cancelOnEnrollmentChannelClosed(requests <-chan *ssh.Request, cancel context.CancelFunc) {
	for req := range requests {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
	cancel()
}

// sendExitStatus sends an exit-status message on an SSH channel
func (s *Server) sendExitStatus(channel ssh.Channel, status uint32) error {
	payload := make([]byte, 4)
	payload[0] = byte(status >> 24)
	payload[1] = byte(status >> 16)
	payload[2] = byte(status >> 8)
	payload[3] = byte(status)
	_, err := channel.SendRequest("exit-status", false, payload)
	return err
}

// handleChannel serves one direct-tcpip channel. The requested destination
// must be loopback; its port is ignored. The channel is handed to the API
// handoff as a connection carrying the client's identity, so the HTTP server
// knows who is calling without any credential in the request.
func (s *Server) handleChannel(sshConn *ssh.ServerConn, info sshConnInfo, newChannel ssh.NewChannel) {
	if newChannel.ChannelType() != "direct-tcpip" {
		if err := newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type"); err != nil {
			fmt.Printf("Failed to reject channel: %v\n", err)
		}
		return
	}

	var req struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(newChannel.ExtraData(), &req); err != nil {
		if err := newChannel.Reject(ssh.Prohibited, "failed to parse port forward request"); err != nil {
			fmt.Printf("Failed to reject channel: %v\n", err)
		}
		return
	}
	if req.DestAddr != "127.0.0.1" && req.DestAddr != "localhost" {
		if err := newChannel.Reject(ssh.Prohibited, "forwarding only allowed to localhost"); err != nil {
			fmt.Printf("Failed to reject channel: %v\n", err)
		}
		return
	}
	if s.apiHandoff == nil || info.fingerprint == "" {
		if err := newChannel.Reject(ssh.Prohibited, "API forwarding is not available"); err != nil {
			fmt.Printf("Failed to reject channel: %v\n", err)
		}
		return
	}

	// Hand the connection over before accepting the channel, so a full or
	// closed listener refuses the channel instead of accepting and dropping it.
	apiSide, tunnelSide := net.Pipe()
	apiConn := &APIConn{Conn: apiSide, fingerprint: info.fingerprint, remote: sshConn.RemoteAddr(), local: sshConn.LocalAddr()}
	if err := s.apiHandoff(apiConn); err != nil {
		_ = apiSide.Close()
		_ = tunnelSide.Close()
		if err := newChannel.Reject(ssh.ResourceShortage, "API listener unavailable"); err != nil && !isClosedConnError(err) {
			fmt.Printf("Failed to reject channel: %v\n", err)
		}
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		_ = tunnelSide.Close()
		return
	}
	go ssh.DiscardRequests(requests)

	// The forwarded connection lives exactly as long as both of its halves.
	// net.Pipe has no half-close, and the HTTP server treats a client's EOF
	// as abandonment of the request anyway (it cancels the request context),
	// so whichever side finishes first tears the whole connection down: the
	// client going away cancels the in-flight request and frees the HTTP
	// side at once, and the HTTP side closing ends the channel instead of
	// waiting for the client to notice its EOF.
	var teardown sync.Once
	closeBoth := func() {
		teardown.Do(func() {
			_ = tunnelSide.Close()
			if err := channel.Close(); err != nil && !isClosedConnError(err) {
				fmt.Printf("Failed to close SSH channel: %v\n", err)
			}
		})
	}
	defer closeBoth()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer closeBoth()
		if _, err := io.Copy(channel, tunnelSide); err != nil && !isClosedConnError(err) && !errors.Is(err, io.ErrClosedPipe) {
			fmt.Printf("Error copying API to channel: %v\n", err)
		}
		// Everything the HTTP side wrote has been handed to the channel (a
		// pipe write returns only once read), so the client sees an orderly
		// EOF before the close that follows.
		if err := channel.CloseWrite(); err != nil && !isClosedConnError(err) {
			fmt.Printf("Failed to close channel write: %v\n", err)
		}
	}()
	go func() {
		defer wg.Done()
		defer closeBoth()
		if _, err := io.Copy(tunnelSide, channel); err != nil && !isClosedConnError(err) && !errors.Is(err, io.ErrClosedPipe) {
			fmt.Printf("Error copying channel to API: %v\n", err)
		}
	}()
	wg.Wait()
}

// Stop stops the SSH server gracefully, waiting for active connections to close.
func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.StopContext(ctx)
}

// StopContext stops the SSH server and reports when the caller's shutdown
// deadline expires before every accept/connection handler has returned.
func (s *Server) StopContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}

	close(s.closeChan)

	listener := s.listener
	s.listener = nil
	s.running = false
	s.mu.Unlock()

	var listenerErr error
	if listener != nil {
		if err := listener.Close(); err != nil && !isClosedConnError(err) {
			listenerErr = fmt.Errorf("failed to close listener: %w", err)
		}
	}

	// Snapshot sockets awaiting active tracking and active SSH connections
	// together; their handoff uses the same lock.
	s.sshConnsMu.Lock()
	rawConns := make([]net.Conn, 0, len(s.rawConns))
	for conn := range s.rawConns {
		rawConns = append(rawConns, conn)
	}
	conns := make([]*ssh.ServerConn, 0, len(s.sshConns))
	for conn := range s.sshConns {
		conns = append(conns, conn)
	}
	s.sshConnsMu.Unlock()
	for _, conn := range rawConns {
		_ = conn.Close()
	}

	// Close all active SSH connections
	for _, conn := range conns {
		if err := conn.Close(); err != nil && !isClosedConnError(err) {
			fmt.Printf("Failed to close SSH connection during shutdown: %v\n", err)
		}
	}

	// Wait for connection handlers to finish (with timeout)
	done := make(chan struct{})
	go func() {
		s.activeConns.Wait()
		close(done)
	}()

	select {
	case <-done:
		return listenerErr
	case <-ctx.Done():
		waitErr := fmt.Errorf("waiting for SSH handlers to close: %w", ctx.Err())
		return errors.Join(listenerErr, waitErr)
	}
}

// ListenAddr returns the address the server is listening on, or "" before
// Start.
func (s *Server) ListenAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// HostPublicKey returns the server's host public key, which clients pin in
// known_hosts.
func (s *Server) HostPublicKey() ssh.PublicKey {
	return s.hostKey.PublicKey()
}

// GetHostKeyFingerprint returns the SSH host key fingerprint for verification
func (s *Server) GetHostKeyFingerprint() string {
	return ssh.FingerprintSHA256(s.hostKey.PublicKey())
}
