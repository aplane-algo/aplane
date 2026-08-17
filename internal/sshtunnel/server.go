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
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
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
type SessionCallback func(remoteAddr string, connected bool)

// TokenApprovalCallback is called to request operator approval for token provisioning.
// Returns true if the operator approved, false if rejected.
type TokenApprovalCallback func(sshFingerprint, remoteAddr string) (approved bool, err error)

// TokenApprovalContextCallback is called to request operator approval for token
// provisioning and is canceled when the SSH client disconnects.
type TokenApprovalContextCallback func(ctx context.Context, sshFingerprint, remoteAddr string) (approved bool, err error)

// TokenIssuanceCallback is called after approval and key enrollment to load or generate the token.
// It must not log success or audit — the caller handles that after confirming delivery.
type TokenIssuanceCallback func() (token string, err error)

// TokenAuditCallback is called after the token has been successfully delivered to the client.
type TokenAuditCallback func(sshFingerprint, remoteAddr string)

// OperatorCheckCallback is called to check if the product operator is connected.
type OperatorCheckCallback func() bool

// TokenMACFunc computes the server and expected client token-proof MACs from
// one identity token-generation snapshot. The raw token remains with the
// identity authenticator.
type TokenMACFunc func(serverInput, clientInput []byte) (serverMAC, clientMAC []byte, tokenGeneration uint64, valid bool)

// KeyCheckerFunc checks whether a public key is authorized for the given identity.
type KeyCheckerFunc func(key ssh.PublicKey) bool

// KeyEnrollerFunc enrolls a public key for the given identity.
type KeyEnrollerFunc func(key ssh.PublicKey) error

// AdminChannelCallback handles an accepted admin subsystem channel.
// The channel is already authenticated at the SSH layer.
type AdminChannelCallback func(channel ssh.Channel, remoteAddr string)

// ProductHooks configures product token validation and SSH key storage.
type ProductHooks struct {
	ComputeTokenMACs TokenMACFunc
	CheckKey         KeyCheckerFunc
	EnrollKey        KeyEnrollerFunc
}

// TokenProvisioningHooks configures the operator-approved request-token flow.
// The sshtunnel layer interleaves key enrollment between approval and issuance,
// and calls AuditProvisioned only after confirming token delivery to the client.
type TokenProvisioningHooks struct {
	Approve           TokenApprovalCallback
	ApproveContext    TokenApprovalContextCallback
	Issue             TokenIssuanceCallback
	AuditProvisioned  TokenAuditCallback
	OperatorConnected OperatorCheckCallback
}

const (
	// AdminSubsystemName is the SSH subsystem name used for remote adminproto.
	AdminSubsystemName = "aplane-admin"

	initialAcceptErrorBackoff = 25 * time.Millisecond
	maxAcceptErrorBackoff     = time.Second
	invalidTokenProofDelay    = 5 * time.Second
)

// Server represents an SSH server with mutual token proof and public-key auth.
type Server struct {
	listenAddr      string          // Address to listen on (e.g., "127.0.0.1:2222")
	targetAddr      string          // Local address to forward connections to (e.g., "127.0.0.1:15283")
	sessionCallback SessionCallback // Optional callback for session events

	sshConfig          *ssh.ServerConfig
	listener           net.Listener
	hostKey            ssh.Signer
	authKeys           []ssh.PublicKey
	authKeysMu         sync.RWMutex // Protects authKeys
	authKeysFileMu     sync.Mutex   // Serializes authorized_keys file appends
	authorizedKeysPath string       // Path to authorized_keys file

	// Authentication
	tokenMu       sync.RWMutex
	expectedToken string // API token used when tokenMAC is nil

	// Optional product callbacks (override built-in single-token/single-keyfile behavior)
	tokenMAC    TokenMACFunc    // If set, computes identity-scoped token proof MACs
	keyChecker  KeyCheckerFunc  // If set, replaces authKeys lookup
	keyEnroller KeyEnrollerFunc // If set, replaces registerAuthorizedKey

	adminChannelCallback AdminChannelCallback

	// Token provisioning callbacks
	tokenApprovalCallback TokenApprovalContextCallback // Called to request operator approval
	tokenIssuanceCallback TokenIssuanceCallback        // Called to load/generate the token
	tokenAuditCallback    TokenAuditCallback           // Called after confirmed delivery
	operatorCheckCallback OperatorCheckCallback        // Called to check if operator is connected

	mu        sync.Mutex
	started   bool
	running   bool
	closeChan chan struct{}

	// Connection tracking for graceful shutdown
	activeConns              sync.WaitGroup                  // Tracks active connection handlers
	sshConns                 map[*ssh.ServerConn]sshConnInfo // Active SSH connections for explicit close
	minimumTokenGeneration   uint64                          // Minimum accepted product token generation
	sshConnsMu               sync.Mutex                      // Protects sshConns and minimumTokenGeneration
	testAfterAuthBeforeTrack func()                          // Test hook for auth/revocation race coverage
	invalidTokenDelay        time.Duration                   // Tests may set this to zero to avoid the production rejection delay
}

type sshConnInfo struct {
	tokenGeneration uint64
}

// SetSessionCallback sets a callback for session connect/disconnect events.
// Callbacks are immutable after Start.
func (s *Server) SetSessionCallback(cb SessionCallback) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assertNotStartedLocked("SetSessionCallback")
	s.sessionCallback = cb
}

// SetTokenProvisioningHooks configures all token provisioning hooks together.
// Hooks are immutable after Start.
func (s *Server) SetTokenProvisioningHooks(hooks TokenProvisioningHooks) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assertNotStartedLocked("SetTokenProvisioningHooks")
	s.tokenApprovalCallback = hooks.ApproveContext
	if s.tokenApprovalCallback == nil && hooks.Approve != nil {
		s.tokenApprovalCallback = func(ctx context.Context, sshFingerprint, remoteAddr string) (bool, error) {
			_ = ctx
			return hooks.Approve(sshFingerprint, remoteAddr)
		}
	}
	s.tokenIssuanceCallback = hooks.Issue
	s.tokenAuditCallback = hooks.AuditProvisioned
	s.operatorCheckCallback = hooks.OperatorConnected
}

// UpdateToken replaces the expected token and closes all active SSH connections.
// Existing connections were authenticated with the old token and must reconnect.
func (s *Server) UpdateToken(newToken string) {
	s.tokenMu.Lock()
	s.expectedToken = newToken
	s.tokenMu.Unlock()

	// Close all active SSH connections (authenticated with old token)
	s.sshConnsMu.Lock()
	conns := make([]*ssh.ServerConn, 0, len(s.sshConns))
	for conn := range s.sshConns {
		conns = append(conns, conn)
	}
	s.sshConnsMu.Unlock()

	for _, conn := range conns {
		// Signal reason before closing so client can display a useful message
		_, _, _ = conn.SendRequest("token-revoked@aplane", false, nil)
		_ = conn.Close()
	}
}

// CloseProductConnections closes active SSH connections authenticated with an
// older product token generation. The authenticator is updated before this is
// called, and the minimum generation closes the auth-before-track race.
func (s *Server) CloseProductConnections(minTokenGeneration uint64, reason string) {
	s.sshConnsMu.Lock()
	conns := make([]*ssh.ServerConn, 0, len(s.sshConns))
	if minTokenGeneration > 0 {
		if minTokenGeneration > s.minimumTokenGeneration {
			s.minimumTokenGeneration = minTokenGeneration
		}
	}
	for conn, info := range s.sshConns {
		if minTokenGeneration == 0 || info.tokenGeneration < minTokenGeneration {
			conns = append(conns, conn)
		}
	}
	s.sshConnsMu.Unlock()

	payload := []byte(reason)
	for _, conn := range conns {
		_, _, _ = conn.SendRequest("token-revoked@aplane", false, payload)
		_ = conn.Close()
	}
}

// ActiveConnectionCount returns the number of active SSH client connections.
func (s *Server) ActiveConnectionCount() int {
	s.sshConnsMu.Lock()
	n := len(s.sshConns)
	s.sshConnsMu.Unlock()
	return n
}

// SetProductHooks configures product token validation and SSH key storage.
// Hooks are immutable after Start.
func (s *Server) SetProductHooks(hooks ProductHooks) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assertNotStartedLocked("SetProductHooks")
	if err := validateProductHooks(hooks); err != nil {
		panic(err.Error())
	}
	s.tokenMAC = hooks.ComputeTokenMACs
	s.keyChecker = hooks.CheckKey
	s.keyEnroller = hooks.EnrollKey
}

func validateProductHooks(hooks ProductHooks) error {
	if !productHooksConfigured(hooks.ComputeTokenMACs, hooks.CheckKey, hooks.EnrollKey) {
		return nil
	}
	if !productHooksComplete(hooks.ComputeTokenMACs, hooks.CheckKey, hooks.EnrollKey) {
		return fmt.Errorf("product SSH hooks require ComputeTokenMACs, CheckKey, and EnrollKey together")
	}
	return nil
}

func productHooksConfigured(tokenMAC TokenMACFunc, keyChecker KeyCheckerFunc, keyEnroller KeyEnrollerFunc) bool {
	return tokenMAC != nil || keyChecker != nil || keyEnroller != nil
}

func productHooksComplete(tokenMAC TokenMACFunc, keyChecker KeyCheckerFunc, keyEnroller KeyEnrollerFunc) bool {
	return tokenMAC != nil && keyChecker != nil && keyEnroller != nil
}

// SetAdminChannelCallback sets the callback used to handle remote admin
// sessions over the dedicated SSH subsystem.
// Callbacks are immutable after Start.
func (s *Server) SetAdminChannelCallback(cb AdminChannelCallback) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assertNotStartedLocked("SetAdminChannelCallback")
	s.adminChannelCallback = cb
}

func (s *Server) assertNotStartedLocked(method string) {
	if s.started {
		panic(fmt.Sprintf("sshtunnel.Server.%s cannot be called after Start", method))
	}
}

// NewServer creates an SSH server with public-key auth and mutual token proof.
//
// Authentication requires both:
//   - Valid SSH public key (enrolled via request-token or manually added to authorized_keys)
//   - Mutual proof of the identity API token
func NewServer(listenAddr, targetAddr, hostKeyPath, authorizedKeysPath, expectedToken string) (*Server, error) {
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
		closeChan:          make(chan struct{}),
		sshConns:           make(map[*ssh.ServerConn]sshConnInfo),
		invalidTokenDelay:  invalidTokenProofDelay,
	}

	server.sshConfig = &ssh.ServerConfig{
		PublicKeyCallback:         server.handlePublicKeyAuth,
		VerifiedPublicKeyCallback: server.handleVerifiedPublicKeyAuth,
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
		var partial *ssh.PartialSuccessError
		if errors.As(err, &partial) {
			outcome = "partial"
		}
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

// handlePublicKeyAuth validates identity/key eligibility. Normal authentication
// remains incomplete until handleVerifiedPublicKeyAuth transitions to mutual
// token proof after SSH verifies possession of the private key.
//
// Special mode: If username is "request-token:default", this is a token provisioning
// request. Only key authentication is required (no token). Fails fast if no operator connected.
func (s *Server) handlePublicKeyAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	remoteAddr := conn.RemoteAddr().String()
	keyFingerprint := ssh.FingerprintSHA256(key)
	username := conn.User()

	if username == "request-token:"+auth.CurrentProductIdentityID() {
		return s.handleTokenProvisioningAuth(conn, key, username, remoteAddr, keyFingerprint)
	}
	if username != auth.CurrentProductIdentityID() {
		return nil, fmt.Errorf("unsupported SSH username: only %q is accepted", auth.CurrentProductIdentityID())
	}

	var authorized bool
	if productHooksConfigured(s.tokenMAC, s.keyChecker, s.keyEnroller) {
		if !productHooksComplete(s.tokenMAC, s.keyChecker, s.keyEnroller) {
			fmt.Printf("[SSH] Product auth is not fully configured for %s (key: %s)\n", remoteAddr, keyFingerprint)
			return nil, fmt.Errorf("product SSH authentication is not fully configured")
		}
		authorized = s.keyChecker(key)
	} else {
		s.authKeysMu.RLock()
		for _, allowedKey := range s.authKeys {
			if bytes.Equal(allowedKey.Marshal(), key.Marshal()) {
				authorized = true
				break
			}
		}
		s.authKeysMu.RUnlock()
	}

	// Reject unknown keys — all key enrollment goes through request-token
	if !authorized {
		fmt.Printf("[SSH] Rejected unknown key from %s: %s\n", remoteAddr, keyFingerprint)
		return nil, fmt.Errorf("unknown key %s; use request-token to enroll", keyFingerprint)
	}
	return &ssh.Permissions{Extensions: map[string]string{
		"auth_method":     "publickey_pending_token_proof",
		"key_fingerprint": keyFingerprint,
		"identity_id":     auth.CurrentProductIdentityID(),
	}}, nil
}

func (s *Server) handleVerifiedPublicKeyAuth(conn ssh.ConnMetadata, key ssh.PublicKey, permissions *ssh.Permissions, _ string) (*ssh.Permissions, error) {
	if permissions == nil || permissions.Extensions == nil {
		return nil, fmt.Errorf("SSH public-key permissions are missing")
	}
	if permissions.Extensions["auth_method"] == "token_provisioning" {
		return permissions, nil
	}

	keyFingerprint := permissions.Extensions["key_fingerprint"]
	if keyFingerprint == "" {
		return nil, fmt.Errorf("SSH public-key identity binding is incomplete")
	}
	fmt.Printf("[SSH] Verified enrolled key from %s: %s\n", conn.RemoteAddr(), keyFingerprint)

	return permissions, &ssh.PartialSuccessError{
		Next: ssh.ServerAuthCallbacks{
			KeyboardInteractiveCallback: func(nextConn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
				return s.handleTokenProofAuth(nextConn, challenge, keyFingerprint)
			},
		},
	}
}

func (s *Server) handleTokenProofAuth(conn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge, keyFingerprint string) (*ssh.Permissions, error) {
	clientNonceQuestion, err := marshalClientNonceQuestion()
	if err != nil {
		return nil, err
	}
	answers, err := challenge(tokenProofDomain, "", []string{clientNonceQuestion}, []bool{false})
	if err != nil {
		return nil, fmt.Errorf("request token proof client nonce: %w", err)
	}
	if len(answers) != 1 {
		return s.rejectTokenProof(conn, keyFingerprint, "invalid client nonce response")
	}
	clientNonce, err := parseClientNonceAnswer(answers[0])
	if err != nil {
		return s.rejectTokenProof(conn, keyFingerprint, "invalid client nonce response")
	}

	serverNonce := make([]byte, tokenProofNonceSize)
	if _, err := rand.Read(serverNonce); err != nil {
		return nil, fmt.Errorf("generate token proof server nonce: %w", err)
	}
	hostKeyHash, err := hashSSHHostKey(s.hostKey.PublicKey())
	if err != nil {
		return nil, err
	}
	transcript, err := encodeTokenProofTranscript(tokenProofTranscript{
		Identity:    auth.CurrentProductIdentityID(),
		HostKeyHash: hostKeyHash,
		ClientNonce: clientNonce,
		ServerNonce: serverNonce,
	})
	if err != nil {
		return nil, err
	}
	serverInput, err := encodeTokenProofMACInput(tokenProofServerDomain, transcript)
	if err != nil {
		return nil, err
	}
	clientInput, err := encodeTokenProofMACInput(tokenProofClientDomain, transcript)
	if err != nil {
		return nil, err
	}

	serverProof, expectedClientProof, tokenGeneration, valid := s.computeTokenMACs(serverInput, clientInput)
	if !valid || len(serverProof) != tokenProofMACSize || len(expectedClientProof) != tokenProofMACSize {
		return s.rejectTokenProof(conn, keyFingerprint, "token proof unavailable")
	}
	serverProofQuestion, err := marshalServerProofQuestion(serverNonce, serverProof)
	if err != nil {
		return nil, err
	}
	answers, err = challenge(tokenProofDomain, "", []string{serverProofQuestion}, []bool{false})
	if err != nil {
		return nil, fmt.Errorf("request token proof client proof: %w", err)
	}
	if len(answers) != 1 {
		return s.rejectTokenProof(conn, keyFingerprint, "invalid client proof response")
	}
	clientProof, err := parseClientProofAnswer(answers[0])
	if err != nil || !verifyTokenProof(expectedClientProof, clientProof) {
		return s.rejectTokenProof(conn, keyFingerprint, "invalid client proof")
	}

	extensions := map[string]string{
		"auth_method":     "publickey+token-proof",
		"identity_id":     auth.CurrentProductIdentityID(),
		"key_fingerprint": keyFingerprint,
	}
	if tokenGeneration > 0 {
		extensions["token_generation"] = strconv.FormatUint(tokenGeneration, 10)
	}
	return &ssh.Permissions{Extensions: extensions}, nil
}

func (s *Server) computeTokenMACs(serverInput, clientInput []byte) (serverMAC, clientMAC []byte, generation uint64, valid bool) {
	if s.tokenMAC != nil {
		return s.tokenMAC(serverInput, clientInput)
	}

	s.tokenMu.RLock()
	defer s.tokenMu.RUnlock()
	if s.expectedToken == "" {
		return nil, nil, 0, false
	}
	return computeTokenProofMAC(s.expectedToken, serverInput), computeTokenProofMAC(s.expectedToken, clientInput), 0, true
}

func (s *Server) rejectTokenProof(conn ssh.ConnMetadata, keyFingerprint, reason string) (*ssh.Permissions, error) {
	fmt.Printf("[SSH] Token proof rejected from %s (key: %s)\n", conn.RemoteAddr(), keyFingerprint)
	if s.invalidTokenDelay > 0 {
		time.Sleep(s.invalidTokenDelay)
	}
	return nil, fmt.Errorf("token proof authentication failed: %s", reason)
}

// handleTokenProvisioningAuth handles SSH auth for token provisioning requests.
// Username is exactly "request-token:default".
// Only requires valid SSH key - no token needed (that's what we're requesting!).
// Fails fast if no operator is connected to approve the request.
func (s *Server) handleTokenProvisioningAuth(conn ssh.ConnMetadata, key ssh.PublicKey, username, remoteAddr, keyFingerprint string) (*ssh.Permissions, error) {
	if username != "request-token:"+auth.CurrentProductIdentityID() {
		return nil, fmt.Errorf("unsupported token provisioning username")
	}

	// Note: Operator and callback checks moved to session handler so error messages
	// can be sent through the channel (SSH auth errors don't preserve the message)

	fmt.Printf("[SSH] Token provisioning request from %s (key: %s)\n", remoteAddr, keyFingerprint)

	return &ssh.Permissions{
		Extensions: map[string]string{
			"auth_method":     "token_provisioning",
			"key_fingerprint": keyFingerprint,
			"identity_id":     auth.CurrentProductIdentityID(),
			"public_key":      string(ssh.MarshalAuthorizedKey(key)),
		},
	}, nil
}

// enrollKey enrolls a public key, using the product callback if set,
// otherwise falling back to the built-in single-file registration.
func (s *Server) enrollKey(key ssh.PublicKey) error {
	if productHooksConfigured(s.tokenMAC, s.keyChecker, s.keyEnroller) {
		if !productHooksComplete(s.tokenMAC, s.keyChecker, s.keyEnroller) {
			return fmt.Errorf("product SSH key enrollment is not fully configured")
		}
		return s.keyEnroller(key)
	}
	return s.registerAuthorizedKey(key)
}

// registerAuthorizedKey adds a new public key to the global authorized_keys file and in-memory list.
func (s *Server) registerAuthorizedKey(key ssh.PublicKey) error {
	if s.hasAuthorizedKey(key) {
		return nil
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

	s.authKeysFileMu.Lock()
	defer s.authKeysFileMu.Unlock()

	if s.hasAuthorizedKey(key) {
		return nil
	}

	fileKeys, err := loadAuthorizedKeys(s.authorizedKeysPath)
	if err != nil {
		return err
	}
	if authorizedKeyInList(fileKeys, key) {
		s.authKeysMu.Lock()
		if !authorizedKeyInList(s.authKeys, key) {
			s.authKeys = append(s.authKeys, key)
		}
		s.authKeysMu.Unlock()
		return nil
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
	s.authKeysMu.Lock()
	s.authKeys = append(s.authKeys, key)
	s.authKeysMu.Unlock()

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

	fmt.Printf("SSH server listening on %s (forwarding to %s)\n", s.listenAddr, s.targetAddr)

	// Accept connections in background
	go s.acceptConnections(ctx, listener)

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

		// Handle connection in goroutine
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
	if s.testAfterAuthBeforeTrack != nil {
		s.testAfterAuthBeforeTrack()
	}

	info := sshConnInfo{}
	if sshConn.Permissions != nil {
		if generationText := sshConn.Permissions.Extensions["token_generation"]; generationText != "" {
			if generation, parseErr := strconv.ParseUint(generationText, 10, 64); parseErr == nil {
				info.tokenGeneration = generation
			}
		}
	}

	// Track connection for graceful shutdown and identity-scoped revocation
	s.sshConnsMu.Lock()
	s.sshConns[sshConn] = info
	staleAuth := s.connectionStaleLocked(info)
	s.sshConnsMu.Unlock()

	remoteAddr := sshConn.RemoteAddr().String()

	// Check if this is a token provisioning connection
	isTokenProvisioning := sshConn.Permissions != nil &&
		sshConn.Permissions.Extensions["auth_method"] == "token_provisioning"

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
		// Log session disconnect with resolved identity
		fmt.Printf("[SSH] Client disconnected: %s\n", remoteAddr)
		if connectedLogged && s.sessionCallback != nil {
			s.sessionCallback(remoteAddr, false)
		}
	}()

	if staleAuth {
		_, _, _ = sshConn.SendRequest("token-revoked@aplane", false, []byte("token revoked"))
		return
	}

	// Log successful SSH connection with resolved identity
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

	// Handle channel requests
	for newChannel := range chans {
		if isTokenProvisioning {
			// Token provisioning mode: handle session channels for exec
			s.activeConns.Add(1)
			go func(ch ssh.NewChannel) {
				defer s.activeConns.Done()
				s.handleTokenProvisioningChannel(connCtx, sshConn, ch)
			}(newChannel)
			continue
		}

		switch newChannel.ChannelType() {
		case "direct-tcpip":
			s.activeConns.Add(1)
			go func(ch ssh.NewChannel) {
				defer s.activeConns.Done()
				s.handleChannel(ch)
			}(newChannel)
		case "session":
			s.activeConns.Add(1)
			go func(ch ssh.NewChannel) {
				defer s.activeConns.Done()
				s.handleSessionChannel(sshConn, ch)
			}(newChannel)
		default:
			if err := newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type"); err != nil && !isClosedConnError(err) {
				fmt.Printf("Failed to reject SSH channel: %v\n", err)
			}
		}
	}
}

func (s *Server) handleSessionChannel(sshConn *ssh.ServerConn, newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}

	remoteAddr := sshConn.RemoteAddr().String()
	for req := range requests {
		switch req.Type {
		case "subsystem":
			var payload struct {
				Name string
			}
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				_ = channel.Close()
				return
			}
			if payload.Name != AdminSubsystemName || s.adminChannelCallback == nil {
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				_ = channel.Close()
				return
			}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			s.adminChannelCallback(channel, remoteAddr)
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}

	_ = channel.Close()
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
func (s *Server) handleTokenProvisioningChannel(connCtx context.Context, sshConn *ssh.ServerConn, newChannel ssh.NewChannel) {
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
	approvalCtx, cancelApproval := context.WithCancel(connCtx)
	defer cancelApproval()

	// Get provisioning info from connection permissions
	fingerprint := ""
	if sshConn.Permissions != nil && sshConn.Permissions.Extensions != nil {
		fingerprint = sshConn.Permissions.Extensions["key_fingerprint"]
	}
	remoteAddr := sshConn.RemoteAddr().String()

	// Handle requests on this channel
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
			go cancelOnProvisioningChannelClosed(requests, cancelApproval)

			// Check if operator is connected (moved here from auth so error message reaches client)
			if s.operatorCheckCallback == nil || !s.operatorCheckCallback() {
				fmt.Printf("[SSH] Token provisioning rejected from %s: no operator connected\n", remoteAddr)
				_, _ = channel.Write([]byte("no operator (apadmin) connected to approve token request\n"))
				_ = s.sendExitStatus(channel, 1)
				return
			}

			// Check if token provisioning is configured
			if s.tokenApprovalCallback == nil || s.tokenIssuanceCallback == nil {
				_, _ = channel.Write([]byte("token provisioning not configured on server\n"))
				_ = s.sendExitStatus(channel, 1)
				return
			}

			fmt.Printf("[SSH] Processing product token provisioning from %s\n", remoteAddr)
			fmt.Printf("[SSH] Waiting for operator approval in apadmin for token provisioning request from %s\n", remoteAddr)

			// Step 1: Request operator approval (blocking — waits for apadmin response)
			approved, err := s.tokenApprovalCallback(approvalCtx, fingerprint, remoteAddr)
			if err != nil {
				errMsg := fmt.Sprintf("ERROR: %s\n", err.Error())
				_, _ = channel.Write([]byte(errMsg))
				_ = s.sendExitStatus(channel, 1)
				return
			}
			if !approved {
				_, _ = channel.Write([]byte("ERROR: token provisioning rejected by operator\n"))
				_ = s.sendExitStatus(channel, 1)
				return
			}

			// Step 2: Enroll the client's SSH key (after approval, before token issuance).
			// Key enrollment is idempotent — registerAuthorizedKey checks for duplicates.
			// A key in authorized_keys without a token is harmless (client cannot
			// authenticate without a valid token). But a token on disk without the key
			// enrolled would leave the client unable to connect.
			pubKeyStr := provisioningPublicKeyString(sshConn.Permissions)
			if pubKeyStr == "" {
				fmt.Printf("[SSH] Missing public key for enrollment\n")
				_, _ = channel.Write([]byte("ERROR: failed to enroll SSH key\n"))
				_ = s.sendExitStatus(channel, 1)
				return
			}
			pubKey, _, _, _, parseErr := ssh.ParseAuthorizedKey([]byte(pubKeyStr))
			if parseErr != nil {
				fmt.Printf("[SSH] Failed to parse public key for enrollment: %v\n", parseErr)
				_, _ = channel.Write([]byte("ERROR: failed to enroll SSH key\n"))
				_ = s.sendExitStatus(channel, 1)
				return
			}
			enrollErr := s.enrollKey(pubKey)
			if enrollErr != nil {
				fmt.Printf("[SSH] Failed to enroll product SSH key: %v\n", enrollErr)
				_, _ = channel.Write([]byte("ERROR: failed to enroll SSH key\n"))
				_ = s.sendExitStatus(channel, 1)
				return
			}

			// Step 3: Load or generate the token (persists to disk).
			// If this fails, the key is enrolled but harmless without a token.
			token, err := s.tokenIssuanceCallback()
			if err != nil {
				errMsg := fmt.Sprintf("ERROR: %s\n", err.Error())
				_, _ = channel.Write([]byte(errMsg))
				_ = s.sendExitStatus(channel, 1)
				return
			}

			// Step 4: Send the token. If disconnect or write completion fails,
			// do not audit the request as successful.
			if approvalCtx.Err() != nil {
				fmt.Printf("[SSH] Token provisioning client disconnected before token delivery: %v\n", approvalCtx.Err())
				return
			}
			if _, writeErr := channel.Write([]byte(token + "\n")); writeErr != nil {
				fmt.Printf("[SSH] Failed to send product token to client: %v\n", writeErr)
				_ = s.sendExitStatus(channel, 1)
				return
			}
			if err := s.sendExitStatus(channel, 0); err != nil {
				fmt.Printf("[SSH] Failed to send token provisioning success status: %v\n", err)
				return
			}

			// Step 5: Audit and log success only after the send path completes.
			if s.tokenAuditCallback != nil {
				s.tokenAuditCallback(fingerprint, remoteAddr)
			}
			fmt.Printf("[SSH] Product token provisioned and SSH key enrolled to %s\n", remoteAddr)
			return

		default:
			// Reject other request types
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
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

func cancelOnProvisioningChannelClosed(requests <-chan *ssh.Request, cancel context.CancelFunc) {
	for req := range requests {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
	cancel()
}

func provisioningPublicKeyString(permissions *ssh.Permissions) string {
	if permissions == nil || permissions.Extensions == nil {
		return ""
	}
	return permissions.Extensions["public_key"]
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

func (s *Server) connectionStaleLocked(info sshConnInfo) bool {
	if info.tokenGeneration == 0 {
		return false
	}
	return s.minimumTokenGeneration > 0 && info.tokenGeneration < s.minimumTokenGeneration
}

// GetHostKeyFingerprint returns the SSH host key fingerprint for verification
func (s *Server) GetHostKeyFingerprint() string {
	return ssh.FingerprintSHA256(s.hostKey.PublicKey())
}
