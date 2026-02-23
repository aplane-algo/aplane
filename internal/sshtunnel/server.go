// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package sshtunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
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
type SessionCallback func(remoteAddr, user string, connected bool)

// TokenProvisioningCallback is called when a client requests a token via SSH.
// It should return the token if approved, or an empty string and error if rejected.
// Parameters: identityID, sshFingerprint, remoteAddr
type TokenProvisioningCallback func(identityID, sshFingerprint, remoteAddr string) (token string, err error)

// OperatorCheckCallback is called to check if an operator (apadmin) is connected.
// Used to fail fast on token provisioning requests when no one can approve.
type OperatorCheckCallback func() bool

// Server represents an SSH server with 2FA: public key + API token (passed as username).
type Server struct {
	listenAddr      string          // Address to listen on (e.g., "127.0.0.1:2222")
	targetAddr      string          // Local address to forward connections to (e.g., "127.0.0.1:15283")
	sessionCallback SessionCallback // Optional callback for session events

	sshConfig          *ssh.ServerConfig
	listener           net.Listener
	hostKey            ssh.Signer
	authKeys           []ssh.PublicKey
	authKeysMu         sync.RWMutex // Protects authKeys
	authorizedKeysPath string       // Path to authorized_keys file

	// Authentication
	expectedToken string // API token (must match username)
	autoRegister  bool   // If true, auto-register new keys; if false, reject unknown keys

	// Token provisioning callbacks
	tokenProvisioningCallback TokenProvisioningCallback // Called to request token approval
	operatorCheckCallback     OperatorCheckCallback     // Called to check if operator is connected

	mu        sync.Mutex
	running   bool
	closeChan chan struct{}

	// Connection tracking for graceful shutdown
	activeConns sync.WaitGroup               // Tracks active connection handlers
	sshConns    map[*ssh.ServerConn]struct{} // Active SSH connections for explicit close
	sshConnsMu  sync.Mutex                   // Protects sshConns
}

// SetSessionCallback sets a callback for session connect/disconnect events
func (s *Server) SetSessionCallback(cb SessionCallback) {
	s.sessionCallback = cb
}

// SetTokenProvisioningCallback sets the callback for token provisioning requests.
// This is called when a client connects with username "request-token:<identity>".
func (s *Server) SetTokenProvisioningCallback(cb TokenProvisioningCallback) {
	s.tokenProvisioningCallback = cb
}

// SetOperatorCheckCallback sets the callback to check if an operator is connected.
// Used to fail fast on token provisioning when no one can approve.
func (s *Server) SetOperatorCheckCallback(cb OperatorCheckCallback) {
	s.operatorCheckCallback = cb
}

// NewServer creates a new SSH server with 2FA: public key + API token.
//
// Authentication requires both:
//   - Valid SSH public key (in authorized_keys, or auto-registered if enabled)
//   - Valid API token (passed as the SSH username)
//
// autoRegister controls whether new (unknown) SSH keys are automatically registered:
//   - true: new keys are registered after successful token verification
//   - false: unknown keys are rejected; only pre-registered keys in authorized_keys are allowed
func NewServer(listenAddr, targetAddr, hostKeyPath, authorizedKeysPath, expectedToken string, autoRegister bool) (*Server, error) {
	hostKey, err := loadOrGenerateHostKey(hostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load host key: %w", err)
	}

	authKeys, err := loadAuthorizedKeys(authorizedKeysPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load authorized keys: %w", err)
	}

	server := &Server{
		listenAddr:         listenAddr,
		targetAddr:         targetAddr,
		hostKey:            hostKey,
		authKeys:           authKeys,
		authorizedKeysPath: authorizedKeysPath,
		expectedToken:      expectedToken,
		autoRegister:       autoRegister,
		closeChan:          make(chan struct{}),
		sshConns:           make(map[*ssh.ServerConn]struct{}),
	}

	// Single-step authentication: public key + token (as username)
	server.sshConfig = &ssh.ServerConfig{
		PublicKeyCallback: server.handlePublicKeyAuth,
		ServerVersion:     "SSH-2.0-aPlane",
	}
	server.sshConfig.AddHostKey(hostKey)

	return server, nil
}

// loadOrGenerateHostKey loads a host key from disk or generates and stores a new one.
func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	if path == "" {
		return nil, fmt.Errorf("host key path is empty")
	}

	data, err := os.ReadFile(path)
	if err == nil {
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

	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed to write host key %s: %w", path, err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	return signer, nil
}

// loadAuthorizedKeys loads all keys from an authorized_keys file.
// Returns an empty slice if the file doesn't exist or is empty (TOFU mode).
func loadAuthorizedKeys(path string) ([]ssh.PublicKey, error) {
	if path == "" {
		return nil, fmt.Errorf("authorized keys path is empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist - TOFU mode, will create on first registration
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read authorized keys %s: %w", path, err)
	}

	// Empty file is valid - TOFU mode
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil
	}

	var keys []ssh.PublicKey
	for len(data) > 0 {
		pubKey, _, _, rest, parseErr := ssh.ParseAuthorizedKey(data)
		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse authorized keys %s: %w", path, parseErr)
		}
		keys = append(keys, pubKey)
		data = rest
	}

	return keys, nil
}

// handlePublicKeyAuth validates both the API token (passed as username) and public key.
// Authentication requires both to succeed. If autoRegister is enabled, new keys are
// registered after successful token verification.
//
// Special mode: If username is "request-token:<identity>", this is a token provisioning
// request. Only key authentication is required (no token). Fails fast if no operator connected.
func (s *Server) handlePublicKeyAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	remoteAddr := conn.RemoteAddr().String()
	keyFingerprint := ssh.FingerprintSHA256(key)
	username := conn.User()

	// Check for token provisioning mode: "request-token:<identity>"
	if strings.HasPrefix(username, "request-token:") {
		return s.handleTokenProvisioningAuth(conn, key, username, remoteAddr, keyFingerprint)
	}

	// Normal mode: username is the API token
	providedToken := username

	// Validate token first (constant-time comparison to prevent timing attacks)
	if subtle.ConstantTimeCompare([]byte(providedToken), []byte(s.expectedToken)) != 1 {
		fmt.Printf("[SSH] Invalid token from %s (key: %s)\n", remoteAddr, keyFingerprint)
		time.Sleep(5 * time.Second) // Slow down brute force attempts
		return nil, fmt.Errorf("invalid API token")
	}

	// Check if key is already authorized
	s.authKeysMu.RLock()
	authorized := false
	for _, allowedKey := range s.authKeys {
		if bytes.Equal(allowedKey.Marshal(), key.Marshal()) {
			authorized = true
			break
		}
	}
	s.authKeysMu.RUnlock()

	// Handle unknown keys
	if !authorized {
		if !s.autoRegister {
			fmt.Printf("[SSH] Rejected unknown key from %s: %s (auto-register disabled)\n", remoteAddr, keyFingerprint)
			return nil, fmt.Errorf("unknown key %s; add to authorized_keys manually", keyFingerprint)
		}

		// Auto-register the key (token already verified)
		if err := s.registerAuthorizedKey(key); err != nil {
			fmt.Printf("[SSH] Failed to register key %s: %v\n", keyFingerprint, err)
			return nil, fmt.Errorf("failed to register key: %w", err)
		}
		fmt.Printf("[SSH] New key %s registered and authenticated from %s\n", keyFingerprint, remoteAddr)
	} else {
		fmt.Printf("[SSH] Authenticated known key from %s: %s\n", remoteAddr, keyFingerprint)
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			"auth_method":     "publickey+token",
			"key_fingerprint": keyFingerprint,
		},
	}, nil
}

// handleTokenProvisioningAuth handles SSH auth for token provisioning requests.
// Username format: "request-token:<identity>" (e.g., "request-token:default")
// Only requires valid SSH key - no token needed (that's what we're requesting!).
// Fails fast if no operator is connected to approve the request.
func (s *Server) handleTokenProvisioningAuth(conn ssh.ConnMetadata, key ssh.PublicKey, username, remoteAddr, keyFingerprint string) (*ssh.Permissions, error) {
	// Extract identity from username
	identityID := strings.TrimPrefix(username, "request-token:")
	if identityID == "" {
		return nil, fmt.Errorf("invalid token request format: missing identity")
	}

	// Currently only support "default" identity
	if identityID != "default" {
		return nil, fmt.Errorf("unsupported identity: %s (only 'default' is currently supported)", identityID)
	}

	// Note: Operator and callback checks moved to session handler so error messages
	// can be sent through the channel (SSH auth errors don't preserve the message)

	fmt.Printf("[SSH] Token provisioning request from %s (key: %s) for identity '%s'\n", remoteAddr, keyFingerprint, identityID)

	return &ssh.Permissions{
		Extensions: map[string]string{
			"auth_method":     "token_provisioning",
			"key_fingerprint": keyFingerprint,
			"identity_id":     identityID,
		},
	}, nil
}

// registerAuthorizedKey adds a new public key to the authorized_keys file and in-memory list.
func (s *Server) registerAuthorizedKey(key ssh.PublicKey) error {
	s.authKeysMu.Lock()
	defer s.authKeysMu.Unlock()

	// Double-check key isn't already registered (race condition guard)
	for _, allowedKey := range s.authKeys {
		if bytes.Equal(allowedKey.Marshal(), key.Marshal()) {
			return nil // Already registered
		}
	}

	// Format key for authorized_keys file
	keyLine := string(ssh.MarshalAuthorizedKey(key))

	// Ensure directory exists
	dir := filepath.Dir(s.authorizedKeysPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	// Append to file
	f, err := os.OpenFile(s.authorizedKeysPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open authorized_keys: %w", err)
	}

	if _, err := f.WriteString(keyLine); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to write key: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close authorized_keys: %w", err)
	}

	// Add to in-memory list
	s.authKeys = append(s.authKeys, key)

	return nil
}

// Start begins listening for SSH connections
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}
	s.mu.Unlock()

	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.listenAddr, err)
	}

	s.mu.Lock()
	s.listener = listener
	s.running = true
	s.mu.Unlock()

	fmt.Printf("SSH server listening on %s (forwarding to %s)\n", s.listenAddr, s.targetAddr)

	// Accept connections in background
	go s.acceptConnections(ctx)

	return nil
}

// acceptConnections handles incoming SSH connections
func (s *Server) acceptConnections(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.closeChan:
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.closeChan:
				return
			default:
				continue
			}
		}

		// Handle connection in goroutine
		s.activeConns.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection processes a single SSH connection
func (s *Server) handleConnection(netConn net.Conn) {
	defer s.activeConns.Done() // Signal handler completion (runs last due to LIFO)

	defer func() {
		if err := netConn.Close(); err != nil && !isClosedConnError(err) {
			fmt.Printf("Failed to close network connection: %v\n", err)
		}
	}()

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(netConn, s.sshConfig)
	if err != nil {
		return
	}

	// Track connection for graceful shutdown
	s.sshConnsMu.Lock()
	s.sshConns[sshConn] = struct{}{}
	s.sshConnsMu.Unlock()

	remoteAddr := sshConn.RemoteAddr().String()

	// Check if this is a token provisioning connection
	isTokenProvisioning := sshConn.Permissions != nil &&
		sshConn.Permissions.Extensions["auth_method"] == "token_provisioning"

	// Channel to signal keepalive monitor to stop
	keepaliveDone := make(chan struct{})

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
		// Log session disconnect (user is the API token, so don't log it)
		fmt.Printf("[SSH] Client disconnected: %s\n", remoteAddr)
		if s.sessionCallback != nil {
			s.sessionCallback(remoteAddr, "[token]", false)
		}
	}()

	// Log successful SSH connection (user is the API token, so don't log it)
	fmt.Printf("[SSH] Client connected from %s\n", remoteAddr)
	if s.sessionCallback != nil {
		s.sessionCallback(remoteAddr, "[token]", true)
	}

	// Handle global requests (including keepalives from client)
	go s.handleGlobalRequests(reqs)

	// Start server-side keepalive monitor to detect dead clients
	go s.monitorClientConnection(sshConn, remoteAddr, keepaliveDone)

	// Handle channel requests
	for newChannel := range chans {
		if isTokenProvisioning {
			// Token provisioning mode: handle session channels for exec
			go s.handleTokenProvisioningChannel(sshConn, newChannel)
		} else {
			// Normal mode: handle port forwarding
			go s.handleChannel(newChannel)
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

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			// Send keepalive request to client
			_, _, err := sshConn.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				// Client is not responding - connection is dead
				fmt.Printf("[SSH] Keepalive failed for %s: %v\n", remoteAddr, err)
				// Close the connection to trigger cleanup
				_ = sshConn.Close()
				return
			}
		}
	}
}

// handleTokenProvisioningChannel handles SSH channels for token provisioning.
// Accepts "session" channel type with "exec" request to trigger provisioning.
func (s *Server) handleTokenProvisioningChannel(sshConn *ssh.ServerConn, newChannel ssh.NewChannel) {
	// Only accept session channels for token provisioning
	if newChannel.ChannelType() != "session" {
		if err := newChannel.Reject(ssh.UnknownChannelType, "only session channels supported for token provisioning"); err != nil {
			fmt.Printf("Failed to reject channel: %v\n", err)
		}
		return
	}

	// Accept the channel
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer func() {
		if err := channel.Close(); err != nil && !isClosedConnError(err) {
			fmt.Printf("Failed to close token provisioning channel: %v\n", err)
		}
	}()

	// Get provisioning info from connection permissions
	identityID := ""
	fingerprint := ""
	if sshConn.Permissions != nil && sshConn.Permissions.Extensions != nil {
		identityID = sshConn.Permissions.Extensions["identity_id"]
		fingerprint = sshConn.Permissions.Extensions["key_fingerprint"]
	}
	remoteAddr := sshConn.RemoteAddr().String()

	// Handle requests on this channel
	for req := range requests {
		switch req.Type {
		case "exec":
			// Parse the command (we expect "provision" or similar)
			// The exec payload format is: uint32 length + string command
			if len(req.Payload) < 4 {
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				continue
			}
			cmdLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
			if len(req.Payload) < 4+cmdLen {
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				continue
			}
			command := string(req.Payload[4 : 4+cmdLen])

			// We only handle "provision" command
			if command != "provision" {
				fmt.Printf("[SSH] Unknown provisioning command: %s\n", command)
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				_, _ = channel.Write([]byte("ERROR: unknown command\n"))
				continue
			}

			// Accept the exec request
			if req.WantReply {
				_ = req.Reply(true, nil)
			}

			// Check if operator is connected (moved here from auth so error message reaches client)
			if s.operatorCheckCallback == nil || !s.operatorCheckCallback() {
				fmt.Printf("[SSH] Token provisioning rejected from %s: no operator connected\n", remoteAddr)
				_, _ = channel.Write([]byte("no operator (apadmin) connected to approve token request\n"))
				s.sendExitStatus(channel, 1)
				return
			}

			// Check if token provisioning is configured
			if s.tokenProvisioningCallback == nil {
				_, _ = channel.Write([]byte("token provisioning not configured on server\n"))
				s.sendExitStatus(channel, 1)
				return
			}

			fmt.Printf("[SSH] Processing token provisioning for identity '%s' from %s\n", identityID, remoteAddr)

			token, err := s.tokenProvisioningCallback(identityID, fingerprint, remoteAddr)
			if err != nil {
				errMsg := fmt.Sprintf("ERROR: %s\n", err.Error())
				_, _ = channel.Write([]byte(errMsg))
				s.sendExitStatus(channel, 1)
				return
			}

			// Send the token back
			_, _ = channel.Write([]byte(token + "\n"))
			s.sendExitStatus(channel, 0)
			fmt.Printf("[SSH] Token provisioned for identity '%s' to %s\n", identityID, remoteAddr)
			return

		default:
			// Reject other request types
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// sendExitStatus sends an exit-status message on an SSH channel
func (s *Server) sendExitStatus(channel ssh.Channel, status uint32) {
	payload := make([]byte, 4)
	payload[0] = byte(status >> 24)
	payload[1] = byte(status >> 16)
	payload[2] = byte(status >> 8)
	payload[3] = byte(status)
	_, _ = channel.SendRequest("exit-status", false, payload)
}

// handleChannel processes a single SSH channel (port forward request)
func (s *Server) handleChannel(newChannel ssh.NewChannel) {
	// We only support "direct-tcpip" channel type (port forwarding)
	if newChannel.ChannelType() != "direct-tcpip" {
		if err := newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type"); err != nil {
			fmt.Printf("Failed to reject channel: %v\n", err)
		}
		return
	}

	// Parse the port forward request
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

	// Verify the request is for our local target (HTTP API)
	// We only allow forwarding to the configured target address
	if req.DestAddr != "127.0.0.1" && req.DestAddr != "localhost" {
		if err := newChannel.Reject(ssh.Prohibited, "forwarding only allowed to localhost"); err != nil {
			fmt.Printf("Failed to reject channel: %v\n", err)
		}
		return
	}

	// Accept the channel
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer func() {
		if err := channel.Close(); err != nil && !isClosedConnError(err) {
			fmt.Printf("Failed to close SSH channel: %v\n", err)
		}
	}()

	// Discard all channel requests
	go ssh.DiscardRequests(requests)

	// Connect to local target (HTTP API)
	targetConn, err := net.Dial("tcp", s.targetAddr)
	if err != nil {
		return
	}
	defer func() {
		if err := targetConn.Close(); err != nil && !isClosedConnError(err) {
			fmt.Printf("Failed to close target connection: %v\n", err)
		}
	}()

	// Bidirectional copy between SSH channel and target connection
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(channel, targetConn); err != nil && !isClosedConnError(err) {
			fmt.Printf("Error copying target to channel: %v\n", err)
		}
		if err := channel.CloseWrite(); err != nil && !isClosedConnError(err) {
			fmt.Printf("Failed to close channel write: %v\n", err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(targetConn, channel); err != nil && !isClosedConnError(err) {
			fmt.Printf("Error copying channel to target: %v\n", err)
		}
	}()

	wg.Wait()
}

// Stop stops the SSH server gracefully, waiting for active connections to close.
func (s *Server) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}

	close(s.closeChan)

	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			s.mu.Unlock()
			return fmt.Errorf("failed to close listener: %w", err)
		}
		s.listener = nil
	}

	s.running = false
	s.mu.Unlock()

	// Copy active connections (avoid holding lock during close)
	s.sshConnsMu.Lock()
	conns := make([]*ssh.ServerConn, 0, len(s.sshConns))
	for conn := range s.sshConns {
		conns = append(conns, conn)
	}
	s.sshConnsMu.Unlock()

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
		// Clean shutdown
	case <-time.After(5 * time.Second):
		fmt.Printf("Timeout waiting for %d SSH connections to close\n", len(conns))
	}

	return nil
}

// GetHostKeyFingerprint returns the SSH host key fingerprint for verification
func (s *Server) GetHostKeyFingerprint() string {
	return ssh.FingerprintSHA256(s.hostKey.PublicKey())
}
