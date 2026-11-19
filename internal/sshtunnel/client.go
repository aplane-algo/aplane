// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ErrHostKeyMismatch marks a remote SSH host key that differs from an
// existing known_hosts pin. Callers must treat this as possible interception,
// not as an ordinary unreachable or unenrolled endpoint.
var (
	ErrHostKeyMismatch = errors.New("SSH host key mismatch")
	ErrUnknownHostKey  = errors.New("unknown SSH host key")
	ErrKnownHostsFile  = errors.New("invalid SSH known_hosts file")
	// ErrKeyNotEnrolled marks an SSH handshake the node refused because the
	// client's key is not enrolled there (or was revoked). The client's key
	// is its only credential, so this is the one authentication failure.
	ErrKeyNotEnrolled = errors.New("SSH key not enrolled at this node")
)

// classifyHandshakeError marks an authentication refusal with
// ErrKeyNotEnrolled. The SSH library reports it only as text.
func classifyHandshakeError(err error) error {
	if err != nil && strings.Contains(err.Error(), "unable to authenticate") {
		return fmt.Errorf("%w: %w", ErrKeyNotEnrolled, err)
	}
	return err
}

// logger returns the SSH client's logger. It is made at each call, because a
// logger kept from package initialization would miss the handler the host installs.
func logger() *slog.Logger {
	return slog.With("component", "ssh")
}

// IdentityCreated describes an identity key generated while connecting.
type IdentityCreated struct {
	Path        string
	Fingerprint string
}

// HostKeyApprovalTimeoutNotice is shared by the shell and console prompts.
func HostKeyApprovalTimeoutNotice() string {
	return fmt.Sprintf("Timeout %.0f seconds", sshHandshakeTimeout.Seconds())
}

type keepaliveStopSignal struct {
	ch   chan struct{}
	once sync.Once
}

func newKeepaliveStopSignal() *keepaliveStopSignal {
	return &keepaliveStopSignal{ch: make(chan struct{})}
}

func (s *keepaliveStopSignal) done() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.ch
}

func (s *keepaliveStopSignal) stop() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		close(s.ch)
	})
}

// HostKeyApprovalHandler is called when connecting to an unknown SSH server. It
// owns the prompt: it should show the user the host, the fingerprint, and
// HostKeyApprovalTimeoutNotice, and return true if the server is trusted.
type HostKeyApprovalHandler func(host string, fingerprint string) (bool, error)

// Client is an SSH connection to a node, authenticated by the client's
// enrolled key. It opens a channel to the node's REST API for each HTTP
// connection (DialSignerAPI); nothing listens on this machine, so no other
// local process can use the client's identity.
type Client struct {
	host    string // remote host
	sshPort int    // SSH port on remote host

	sshClient *ssh.Client
	agentConn net.Conn

	identityFile      string
	knownHostsPath    string
	hostKeyApproval   HostKeyApprovalHandler // Callback for TOFU host key approval
	onEnrollmentStart func(string)
	onIdentityCreated func(IdentityCreated)

	mu        sync.Mutex
	connected bool
	closeChan chan struct{}

	// Connection monitoring
	keepaliveInterval time.Duration        // Tests may shorten keepaliveInterval
	keepaliveTimeout  time.Duration        // Tests may shorten keepaliveReplyTimeout
	keepaliveStop     *keepaliveStopSignal // Signal to stop keepalive goroutine
	onDisconnect      func()               // Callback when connection dies
	disconnectReason  string               // Set by server before closing (e.g. "key-revoked")
	interceptDone     chan struct{}        // Closed once the global-request interceptor has drained
}

// DisconnectReasonKeyRevoked is the disconnect reason recorded when the server
// closed the connection because the client's key was revoked.
const DisconnectReasonKeyRevoked = "key-revoked"

// forwardedAPIAddress is the destination named in every direct-tcpip channel
// request. The server (see handleChannel) checks only that the address is
// loopback and always dials its own REST listener, so the port here is
// nominal: a client never chooses the remote port.
const forwardedAPIAddress = "127.0.0.1:11270"

// NewClient creates a new SSH tunnel client.
// host: remote host address
// sshPort: SSH port on remote host
// identityFile: path to SSH private key (optional; if empty, use SSH agent)
// knownHostsPath: path to known_hosts file
func NewClient(host string, sshPort int, identityFile, knownHostsPath string) *Client {
	return &Client{
		host:              host,
		sshPort:           sshPort,
		identityFile:      identityFile,
		knownHostsPath:    knownHostsPath,
		closeChan:         make(chan struct{}),
		keepaliveInterval: keepaliveInterval,
		keepaliveTimeout:  keepaliveReplyTimeout,
		keepaliveStop:     newKeepaliveStopSignal(),
	}
}

// SetDisconnectCallback sets a callback to be called when the connection dies
func (c *Client) SetDisconnectCallback(callback func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onDisconnect = callback
}

// SetIdentityCreatedCallback sets a callback for when connecting generates a new
// identity key, so the host can announce it. Without one, it is logged as a warning.
func (c *Client) SetIdentityCreatedCallback(callback func(IdentityCreated)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onIdentityCreated = callback
}

// SetHostKeyApprovalHandler sets a callback for TOFU host key approval.
// When connecting to an unknown server, this handler will be called to prompt
// the user. If approved, the host key is saved to known_hosts.
func (c *Client) SetHostKeyApprovalHandler(handler HostKeyApprovalHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hostKeyApproval = handler
}

// SetEnrollmentStartCallback sets a callback for enrollment after the SSH
// session starts the remote enroll command. Its argument is the complete
// SHA256 fingerprint of the client key used for authentication.
func (c *Client) SetEnrollmentStartCallback(callback func(string)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onEnrollmentStart = callback
}

// ConnectWithKey establishes an SSH connection authenticated by the client's
// enrolled key. The server is authenticated by its host key against
// known_hosts; no other credential is involved.
func (c *Client) ConnectWithKey(ctx context.Context) error {
	c.mu.Lock()
	if c.connected {
		c.mu.Unlock()
		return fmt.Errorf("already connected")
	}
	c.resetCloseSignalLocked()
	c.mu.Unlock()

	authMethod, agentConn, err := c.authMethod(nil)
	if err != nil {
		return err
	}

	hostKeyCallback, err := c.hostKeyCallback()
	if err != nil {
		if agentConn != nil {
			_ = agentConn.Close()
		}
		return err
	}

	config := &ssh.ClientConfig{
		User:            productSSHUsername,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: hostKeyCallback,
		Timeout:         sshHandshakeTimeout,
	}

	// Connect to SSH server
	addr := net.JoinHostPort(c.host, fmt.Sprint(c.sshPort))

	sshClient, interceptDone, err := c.dialAndIntercept(ctx, "tcp", addr, config)
	if err != nil {
		if agentConn != nil {
			_ = agentConn.Close()
		}
		return fmt.Errorf("SSH connection failed: %w", classifyHandshakeError(err))
	}

	c.mu.Lock()
	c.sshClient = sshClient
	c.interceptDone = interceptDone
	c.agentConn = agentConn
	c.connected = true
	c.disconnectReason = ""
	// Recreate keepaliveStop in case this is a reconnection.
	keepaliveStop := newKeepaliveStopSignal()
	c.keepaliveStop = keepaliveStop
	c.mu.Unlock()

	// Start connection monitoring
	go c.monitorConnection(ctx, sshClient, keepaliveStop)

	return nil
}

// authMethod is the client's credential: the SSH agent's keys when it has no
// identity file, otherwise the identity file, created when it is missing. The
// identity file is the key the node enrolled, so failing to create it is an
// error, never a switch to the agent's keys, which would offer (and could
// enroll) a key the user never meant for aplane. When another process
// created the file first, the key it wrote is used.
func (c *Client) authMethod(onSigned func(string)) (ssh.AuthMethod, net.Conn, error) {
	if c.identityFile == "" {
		return c.agentAuthMethod(onSigned)
	}
	identityPath := expandUserPath(c.identityFile)
	keyData, err := os.ReadFile(identityPath)
	if os.IsNotExist(err) {
		signer, genErr := c.generateIdentityKey(identityPath)
		if genErr == nil {
			return ssh.PublicKeys(observeAuthSigner(signer, onSigned)), nil, nil
		}
		if !errors.Is(genErr, fs.ErrExist) {
			return nil, nil, fmt.Errorf("create SSH identity %s: %w", identityPath, genErr)
		}
		keyData, err = os.ReadFile(identityPath)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read SSH identity file %s: %w", identityPath, err)
	}
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			return nil, nil, fmt.Errorf("the SSH key at %s is encrypted, so apshell can't use it; "+
				"point the endpoint's identity_file at an unencrypted key", identityPath)
		}
		return nil, nil, fmt.Errorf("failed to parse SSH identity file %s: %w", identityPath, err)
	}
	return ssh.PublicKeys(observeAuthSigner(signer, onSigned)), nil, nil
}

// generateIdentityKey creates a new Ed25519 key pair and saves it to the specified path.
// Returns the signer for immediate use. ReadIdentityPublicKey gets the public key.
func (c *Client) generateIdentityKey(path string) (ssh.Signer, error) {
	pubKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	// Marshal private key to OpenSSH format
	pemBlock, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	// Ensure directory exists
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create directory: %w", err)
		}
	}

	if err := writeNewPrivateKeyFile(path, pemBytes); err != nil {
		return nil, fmt.Errorf("failed to write private key: %w", err)
	}

	// Create signer
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH public key: %w", err)
	}
	c.announceIdentityCreated(IdentityCreated{Path: path, Fingerprint: ssh.FingerprintSHA256(sshPubKey)})

	return signer, nil
}

func (c *Client) announceIdentityCreated(created IdentityCreated) {
	c.mu.Lock()
	callback := c.onIdentityCreated
	c.mu.Unlock()
	if callback != nil {
		callback(created)
		return
	}
	logger().Warn("generated a new SSH identity key", "path", created.Path, "fingerprint", created.Fingerprint)
}

func (c *Client) agentAuthMethod(onSigned func(string)) (ssh.AuthMethod, net.Conn, error) {
	agentSock := os.Getenv("SSH_AUTH_SOCK")
	if agentSock == "" {
		return nil, nil, fmt.Errorf("no SSH identity file configured and SSH_AUTH_SOCK is not set")
	}

	conn, err := net.Dial("unix", agentSock)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to SSH agent: %w", err)
	}

	agentClient := agent.NewClient(conn)
	return ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		signers, err := agentClient.Signers()
		if err != nil {
			return nil, err
		}
		for i, signer := range signers {
			signers[i] = observeAuthSigner(signer, onSigned)
		}
		return signers, nil
	}), conn, nil
}

func (c *Client) hostKeyCallback() (ssh.HostKeyCallback, error) {
	if c.knownHostsPath == "" {
		return nil, fmt.Errorf("known_hosts path is empty")
	}
	knownHostsPath := expandUserPath(c.knownHostsPath)

	// Try to load existing known_hosts file
	var existingCallback ssh.HostKeyCallback
	if _, err := os.Stat(knownHostsPath); err == nil {
		callback, err := knownhosts.New(knownHostsPath)
		if err != nil {
			return nil, fmt.Errorf("%w %s: %v", ErrKnownHostsFile, knownHostsPath, err)
		}
		existingCallback = callback
	}
	// The callback runs at every key exchange of the connection, rekeys
	// included, but known_hosts was read before the first one. So the host
	// key the user approves is remembered here: a later exchange accepts that
	// key and nothing else, and the user is asked at most once.
	var (
		approvalMu  sync.Mutex
		prompted    bool
		approvedKey []byte
	)

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fingerprint := ssh.FingerprintSHA256(key)

		approvalMu.Lock()
		defer approvalMu.Unlock()
		if approvedKey != nil {
			if bytes.Equal(key.Marshal(), approvedKey) {
				return nil
			}
			return fmt.Errorf("%w for %s: the key changed after it was approved (possible MITM attack)", ErrHostKeyMismatch, hostname)
		}

		// Check against existing known_hosts if available
		if existingCallback != nil {
			err := existingCallback(hostname, remote, key)
			if err == nil {
				return nil // Host is known and key matches
			}
			if keyErr, ok := err.(*knownhosts.KeyError); ok {
				if len(keyErr.Want) > 0 {
					// Key mismatch - this is a security issue, don't allow TOFU
					return fmt.Errorf("%w for %s (possible MITM attack)", ErrHostKeyMismatch, hostname)
				}
				// Host not in known_hosts - fall through to TOFU
			} else {
				return err
			}
		}

		// Unknown host - attempt TOFU
		c.mu.Lock()
		handler := c.hostKeyApproval
		c.mu.Unlock()

		if handler == nil {
			return fmt.Errorf("%w %s (key %s); add it to %s or set approval handler", ErrUnknownHostKey, hostname, fingerprint, knownHostsPath)
		}

		// Prompt user for approval (only once per connection attempt)
		if prompted {
			return fmt.Errorf("host key rejected by user")
		}
		prompted = true
		approved, approvalErr := handler(hostname, fingerprint)
		if approvalErr != nil {
			return fmt.Errorf("host key approval failed: %w", approvalErr)
		}
		if !approved {
			return fmt.Errorf("host key rejected by user")
		}

		// Save to known_hosts
		if err := c.saveHostKey(knownHostsPath, hostname, key); err != nil {
			return fmt.Errorf("failed to save host key: %w", err)
		}
		logger().Info("host key saved", "path", knownHostsPath)
		approvedKey = key.Marshal()

		return nil
	}, nil
}

func (c *Client) resetCloseSignalLocked() {
	select {
	case <-c.closeChan:
		c.closeChan = make(chan struct{})
	default:
	}
}

// saveHostKey appends a host key to the known_hosts file.
func (c *Client) saveHostKey(knownHostsPath, hostname string, key ssh.PublicKey) error {
	// Ensure directory exists
	dir := filepath.Dir(knownHostsPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	// Format the known_hosts line
	// Format: hostname key-type base64-key
	line := knownhosts.Line([]string{hostname}, key)

	// Append to file
	f, err := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open known_hosts: %w", err)
	}

	if _, err := f.WriteString(line + "\n"); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to write host key: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to save known_hosts: %w", err)
	}

	return nil
}

func expandUserPath(path string) string {
	if path == "" || !strings.HasPrefix(path, "~") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	if strings.HasPrefix(path, "~/") {
		return home + path[1:]
	}
	return path
}

// Close closes the SSH connection.
func (c *Client) Close() error {
	c.mu.Lock()

	// Prevent double-close
	select {
	case <-c.closeChan:
		// Already closed
		c.mu.Unlock()
		return nil
	default:
		close(c.closeChan)
	}

	keepaliveStop := c.keepaliveStop

	c.mu.Unlock()

	// Stop keepalive monitoring
	keepaliveStop.stop()

	var errs []error

	c.mu.Lock()
	if c.sshClient != nil {
		if err := c.sshClient.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close SSH client: %w", err))
		}
		c.sshClient = nil
	}
	if c.agentConn != nil {
		if err := c.agentConn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close SSH agent connection: %w", err))
		}
		c.agentConn = nil
	}

	c.connected = false
	c.mu.Unlock()

	if len(errs) > 0 {
		return fmt.Errorf("errors during close: %v", errs)
	}

	return nil
}

// IsConnected returns true if the client is currently connected
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

// DialSignerAPI opens one context-bounded SSH channel to the node's REST
// API. Callers cannot select another remote destination through this method.
func (c *Client) DialSignerAPI(ctx context.Context) (net.Conn, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	c.mu.Lock()
	sshClient := c.sshClient
	connected := c.connected
	c.mu.Unlock()

	if !connected || sshClient == nil {
		return nil, fmt.Errorf("not connected")
	}
	return sshClient.DialContext(ctx, "tcp", forwardedAPIAddress)
}

// EnrollmentResult is a node's answer to an enroll session: the client
// key's fingerprint and whether the request now waits for the operator
// (Pending) or the key was already enrolled.
type EnrollmentResult struct {
	Fingerprint string
	Pending     bool
}

// RequestEnrollment connects as the enrollment user and asks the node to
// enroll this client's key, with an optional display label. It is a one-shot
// operation: connect, submit, receive the answer, disconnect. The request is
// recorded for the operator to approve later; the client learns the outcome
// by connecting. No credential is returned: the key is the credential.
func (c *Client) RequestEnrollment(ctx context.Context, label string) (EnrollmentResult, error) {
	var none EnrollmentResult
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := parseEnrollmentCommand(enrollmentCommandLine(label)); !ok {
		return none, fmt.Errorf("enrollment label must be printable, single-line, and at most %d bytes", maxEnrollmentLabelBytes)
	}
	var clientFingerprint string
	authMethod, agentConn, err := c.authMethod(func(fingerprint string) { clientFingerprint = fingerprint })
	if err != nil {
		return none, err
	}
	if agentConn != nil {
		defer func() { _ = agentConn.Close() }()
	}

	hostKeyCallback, err := c.hostKeyCallback()
	if err != nil {
		return none, err
	}

	config := &ssh.ClientConfig{
		User:            enrollmentSSHUsername,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: hostKeyCallback,
		Timeout:         sshHandshakeTimeout,
	}

	// Connect to SSH server
	addr := net.JoinHostPort(c.host, fmt.Sprint(c.sshPort))
	sshClient, err := dialWithContext(ctx, "tcp", addr, config)
	if err != nil {
		if strings.Contains(err.Error(), "unable to authenticate") {
			// The enrollment username accepts any key of a supported type,
			// so a refusal here is a key-type problem, not enrollment.
			return none, fmt.Errorf("SSH connection failed: %w (client access accepts %s keys)", err, clientKeyRequirement)
		}
		return none, fmt.Errorf("SSH connection failed: %w", err)
	}
	defer func() { _ = sshClient.Close() }()

	// Open a session channel
	session, err := sshClient.NewSession()
	if err != nil {
		return none, fmt.Errorf("failed to create session: %w", err)
	}
	defer func() { _ = session.Close() }()

	stopCancel := context.AfterFunc(ctx, func() {
		_ = session.Close()
		_ = sshClient.Close()
	})
	defer stopCancel()

	// Set up pipes for output
	stdout, err := session.StdoutPipe()
	if err != nil {
		return none, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		return none, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := session.Start(enrollmentCommandLine(label)); err != nil {
		if ctx.Err() != nil {
			return none, ctx.Err()
		}
		return none, fmt.Errorf("failed to start enrollment: %w", err)
	}
	c.mu.Lock()
	onEnrollmentStart := c.onEnrollmentStart
	c.mu.Unlock()
	if onEnrollmentStart != nil {
		onEnrollmentStart(clientFingerprint)
	}

	// Drain stdout (the acknowledgement on success) and stderr (error detail)
	// concurrently: reading them sequentially can deadlock if the remote
	// command fills the unread pipe's window before closing the other.
	var errOutput []byte
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		errOutput, _ = io.ReadAll(stderr)
	}()

	output, err := io.ReadAll(stdout)
	if err != nil {
		if ctx.Err() != nil {
			return none, ctx.Err()
		}
		return none, fmt.Errorf("failed to read response: %w", err)
	}
	<-stderrDone
	if ctx.Err() != nil {
		return none, ctx.Err()
	}

	// Wait for command to complete
	if err := session.Wait(); err != nil {
		if ctx.Err() != nil {
			return none, ctx.Err()
		}
		errMsg := strings.TrimSpace(string(errOutput))
		if errMsg == "" {
			errMsg = strings.TrimSpace(string(output))
		}
		if errMsg != "" {
			return none, fmt.Errorf("%s", errMsg)
		}
		return none, fmt.Errorf("enrollment failed: %w", err)
	}

	reply := strings.TrimSpace(string(output))
	var result EnrollmentResult
	switch {
	case strings.HasPrefix(reply, "pending "):
		result = EnrollmentResult{Fingerprint: strings.TrimPrefix(reply, "pending "), Pending: true}
	case strings.HasPrefix(reply, "enrolled "):
		result = EnrollmentResult{Fingerprint: strings.TrimPrefix(reply, "enrolled ")}
	}
	if result.Fingerprint == "" {
		return none, fmt.Errorf("unexpected enrollment response: %s", quoteClientText(reply))
	}
	if clientFingerprint != "" && result.Fingerprint != clientFingerprint {
		return none, fmt.Errorf("server answered for %s, but this client authenticated with %s", result.Fingerprint, clientFingerprint)
	}
	return result, nil
}

// enrollmentCommandLine renders the exec command for an enrollment request.
func enrollmentCommandLine(label string) string {
	if label == "" {
		return enrollmentCommand
	}
	return enrollmentCommand + " " + label
}

// monitorConnection monitors the SSH connection and detects when it dies
// It runs two detection mechanisms:
//  1. SSH keepalive pings every keepaliveInterval; a ping with no reply within
//     keepaliveTimeout closes the connection (detects a server that went
//     silent: a partition, a suspended VM)
//  2. Wait for SSH connection to close (detects server shutdown)
func (c *Client) monitorConnection(ctx context.Context, sshClient *ssh.Client, keepaliveStop *keepaliveStopSignal) {
	// Start keepalive goroutine
	keepaliveDone := make(chan struct{})
	go func() {
		defer close(keepaliveDone)
		defer func() {
			if r := recover(); r != nil {
				logger().Error("keepalive goroutine panic", "panic", r)
				c.handleDisconnect()
			}
		}()
		ticker := time.NewTicker(c.keepaliveInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-keepaliveStop.done():
				return
			case <-ticker.C:
				// SendRequest waits for the reply until the connection closes,
				// which TCP may take many minutes to notice, so it runs aside
				// and the reply is awaited under a timer, as the server's
				// monitorClientConnection does. Closing the connection
				// unblocks it.
				replied := make(chan error, 1)
				go func() {
					_, _, err := sshClient.SendRequest("keepalive@openssh.com", true, nil)
					replied <- err
				}()
				select {
				case err := <-replied:
					if err != nil {
						// Connection is dead
						logger().Warn("keepalive failed", "error", err)
						c.handleDisconnect()
						return
					}
				case <-time.After(c.keepaliveTimeout):
					logger().Warn("no keepalive reply; closing the connection", "timeout", c.keepaliveTimeout)
					_ = sshClient.Close()
					c.handleDisconnect()
					return
				case <-ctx.Done():
					return
				case <-keepaliveStop.done():
					return
				}
			}
		}
	}()

	// Wait for SSH connection to close (blocks until connection dies)
	// This detects server-side shutdowns
	if err := sshClient.Wait(); err != nil {
		select {
		case <-c.closeChan:
			// Local shutdown path: suppress expected "use of closed network connection" noise.
		default:
			logConnectionError(err)
		}
	}

	// Stop keepalive goroutine
	keepaliveStop.stop()
	<-keepaliveDone

	// The server's revocation notice precedes its close on the wire, and
	// the SSH mux closes the request stream before Wait returns, so the
	// interceptor is about to finish; wait for it so the disconnect reason
	// is in place before the callback reads it.
	c.mu.Lock()
	interceptDone := c.interceptDone
	c.mu.Unlock()
	if interceptDone != nil {
		select {
		case <-interceptDone:
		case <-time.After(time.Second):
		}
	}

	// Handle disconnection
	c.handleDisconnect()
}

// logConnectionError reports why a connection ended, if that says anything: EOF is
// just how a remote close looks, and handleDisconnect reports the close itself.
func logConnectionError(err error) {
	if errors.Is(err, io.EOF) {
		logger().Debug("connection closed", "error", err)
		return
	}
	logger().Warn("connection closed", "error", err)
}

// handleDisconnect is called when the connection dies
func (c *Client) handleDisconnect() {
	c.mu.Lock()
	wasConnected := c.connected
	c.connected = false
	callback := c.onDisconnect
	reason := c.disconnectReason
	c.mu.Unlock()

	// Only report once. A local Close has already cleared connected, so this is the
	// remote side going away. Not every connection has a callback: a cosigner
	// connection doesn't, and its loss must still be reported.
	if !wasConnected {
		return
	}
	if reason == DisconnectReasonKeyRevoked {
		logger().Warn("disconnected: this client's key was revoked by the signer")
	} else {
		logger().Warn("connection closed by remote server")
	}
	if callback != nil {
		callback()
	}
}

// dialAndIntercept connects to the SSH server and intercepts global requests
// from the server (the revocation notice) before forwarding them to
// ssh.NewClient. The returned channel closes once the interceptor has
// drained the request stream, which the SSH mux closes when the connection
// ends.
func (c *Client) dialAndIntercept(ctx context.Context, network, addr string, config *ssh.ClientConfig) (*ssh.Client, chan struct{}, error) {
	sshConn, chans, reqs, err := dialSSHHandshake(ctx, network, addr, config)
	if err != nil {
		return nil, nil, err
	}

	// Intercept global requests: capture server signals, forward the rest
	filteredReqs := make(chan *ssh.Request, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for req := range reqs {
			if req.Type == RevokedRequestType {
				c.mu.Lock()
				c.disconnectReason = DisconnectReasonKeyRevoked
				c.mu.Unlock()
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
				continue
			}
			if !forwardInterceptedGlobalRequest(ctx, filteredReqs, req) {
				return
			}
		}
		close(filteredReqs)
	}()

	client := ssh.NewClient(sshConn, chans, filteredReqs)
	return client, done, nil
}

func forwardInterceptedGlobalRequest(ctx context.Context, filteredReqs chan<- *ssh.Request, req *ssh.Request) bool {
	select {
	case filteredReqs <- req:
		return true
	case <-ctx.Done():
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return false
	default:
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return true
	}
}

// dialWithContext connects to SSH server with context support
func dialWithContext(ctx context.Context, network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	c, chans, reqs, err := dialSSHHandshake(ctx, network, addr, config)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// dialSSHHandshake bounds TCP dialing and authentication together. Cancellation
// closes the socket, including when a read is already blocked. Successful
// connections detach from this setup lifetime before being returned.
func dialSSHHandshake(ctx context.Context, network, addr string, config *ssh.ClientConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = sshHandshakeTimeout
	}
	setupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialNetwork, dialAddr := sshDialTarget(network, addr)
	conn, err := (&net.Dialer{}).DialContext(setupCtx, dialNetwork, dialAddr)
	if err != nil {
		return nil, nil, nil, err
	}
	stop := context.AfterFunc(setupCtx, func() { _ = conn.Close() })
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	detached := stop()
	if err != nil || !detached || setupCtx.Err() != nil {
		_ = conn.Close()
		if setupCtx.Err() != nil {
			err = setupCtx.Err()
		}
		if err == nil {
			err = context.Canceled
		}
		return nil, nil, nil, err
	}
	return sshConn, chans, reqs, nil
}

func sshDialTarget(network, addr string) (string, string) {
	if network != "tcp" {
		return network, addr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return network, addr
	}
	if strings.EqualFold(host, "localhost") {
		return "tcp4", net.JoinHostPort("127.0.0.1", port)
	}
	return network, addr
}
