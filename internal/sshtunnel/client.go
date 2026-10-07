// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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

// statusWriter is the destination for SSH client status/error messages emitted
// from background goroutines (keepalive monitors, connection-closed handlers,
// host-key prompts, identity-key generation). Defaults to os.Stdout so the
// standalone apshell behavior is unchanged. TUI hosts (apconsole) must call
// SetStatusWriter(io.Discard) — otherwise these direct writes corrupt the
// bubbletea-managed display when the tunnel emits between frames.
var (
	statusMu     sync.RWMutex
	statusWriter io.Writer = os.Stdout
)

// SetStatusWriter overrides where SSH client status messages are written.
// Pass io.Discard to suppress them. nil restores the default (os.Stdout).
func SetStatusWriter(w io.Writer) {
	if w == nil {
		w = os.Stdout
	}
	statusMu.Lock()
	statusWriter = w
	statusMu.Unlock()
}

func status() io.Writer {
	statusMu.RLock()
	defer statusMu.RUnlock()
	return statusWriter
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

// HostKeyApprovalHandler is called when connecting to an unknown SSH server.
// It should display the host and fingerprint to the user and return true if trusted.
type HostKeyApprovalHandler func(host string, fingerprint string) (bool, error)

// Client represents an SSH tunnel client with public-key authentication and
// mutual token proof.
type Client struct {
	host      string // remote host
	sshPort   int    // SSH port on remote host
	localPort int    // local port to forward from (auto-selected)

	sshClient *ssh.Client
	listener  net.Listener
	agentConn net.Conn

	identityFile      string
	knownHostsPath    string
	hostKeyApproval   HostKeyApprovalHandler // Callback for TOFU host key approval
	onEnrollmentStart func(string)

	mu        sync.Mutex
	connected bool
	closeChan chan struct{}

	// Connection monitoring
	keepaliveStop    *keepaliveStopSignal // Signal to stop keepalive goroutine
	onDisconnect     func()               // Callback when connection dies
	disconnectReason string               // Set by server before closing (e.g. "key-revoked")
}

// DisconnectReasonKeyRevoked is the disconnect reason recorded when the server
// closed the connection because the client's key was revoked.
const DisconnectReasonKeyRevoked = "key-revoked"

// forwardedAPIAddress is the destination named in every direct-tcpip channel
// request. The server (see handleDirectTCPIP) checks only that the address is
// loopback and always dials its own REST listener, so the port here is
// nominal: a client never chooses the remote port.
const forwardedAPIAddress = "127.0.0.1:11270"

// NewClient creates a new SSH tunnel client.
// host: remote host address
// sshPort: SSH port on remote host
// localPort: local port for tunnel (auto-selected by caller)
// identityFile: path to SSH private key (optional; if empty, use SSH agent)
// knownHostsPath: path to known_hosts file
func NewClient(host string, sshPort, localPort int, identityFile, knownHostsPath string) *Client {
	return &Client{
		host:           host,
		sshPort:        sshPort,
		localPort:      localPort,
		identityFile:   identityFile,
		knownHostsPath: knownHostsPath,
		closeChan:      make(chan struct{}),
		keepaliveStop:  newKeepaliveStopSignal(),
	}
}

// SetDisconnectCallback sets a callback to be called when the connection dies
func (c *Client) SetDisconnectCallback(callback func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onDisconnect = callback
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

	sshClient, err := c.dialAndIntercept(ctx, "tcp", addr, config)
	if err != nil {
		if agentConn != nil {
			_ = agentConn.Close()
		}
		return fmt.Errorf("SSH connection failed: %w", classifyHandshakeError(err))
	}

	c.mu.Lock()
	c.sshClient = sshClient
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

func (c *Client) authMethod(onSigned func(string)) (ssh.AuthMethod, net.Conn, error) {
	if c.identityFile != "" {
		identityPath := expandUserPath(c.identityFile)
		keyData, err := os.ReadFile(identityPath)
		if err != nil {
			if os.IsNotExist(err) {
				// Auto-generate key if it doesn't exist
				signer, genErr := c.generateIdentityKey(identityPath)
				if genErr != nil {
					// Fall back to SSH agent if key generation fails
					return c.agentAuthMethod(onSigned)
				}
				return ssh.PublicKeys(observeAuthSigner(signer, onSigned)), nil, nil
			}
			return nil, nil, fmt.Errorf("failed to read SSH identity file %s: %w", identityPath, err)
		}
		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			if _, ok := err.(*ssh.PassphraseMissingError); ok {
				return nil, nil, fmt.Errorf("SSH identity file %s is encrypted; use ssh-agent or an unencrypted key", identityPath)
			}
			return nil, nil, fmt.Errorf("failed to parse SSH identity file %s: %w", identityPath, err)
		}
		return ssh.PublicKeys(observeAuthSigner(signer, onSigned)), nil, nil
	}

	return c.agentAuthMethod(onSigned)
}

// generateIdentityKey creates a new Ed25519 key pair and saves it to the specified path.
// Returns the signer for immediate use. The public key is printed for the user to register.
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

	// Format public key for display
	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH public key: %w", err)
	}
	authorizedKey := ssh.MarshalAuthorizedKey(sshPubKey)

	_, _ = fmt.Fprintf(status(), "\n[SSH] Generated new identity key: %s\n", path)
	_, _ = fmt.Fprintf(status(), "[SSH] Public key fingerprint: %s\n", ssh.FingerprintSHA256(sshPubKey))
	_, _ = fmt.Fprintf(status(), "[SSH] Public key (for authorized_keys):\n%s\n", string(authorizedKey))

	return signer, nil
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
	var approvalOnce sync.Once

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fingerprint := ssh.FingerprintSHA256(key)

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
		var approved bool
		var approvalErr error
		approvalOnce.Do(func() {
			_, _ = fmt.Fprintf(status(), "\n[SSH] Unknown host: %s\n", hostname)
			_, _ = fmt.Fprintf(status(), "[SSH] Host key fingerprint: %s\n", fingerprint)
			_, _ = fmt.Fprintln(status(), HostKeyApprovalTimeoutNotice())
			approved, approvalErr = handler(hostname, fingerprint)
		})

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
		_, _ = fmt.Fprintf(status(), "[SSH] Host key saved to %s\n", knownHostsPath)

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

// StartPortForwarding starts forwarding local port to remote port through the SSH tunnel
func (c *Client) StartPortForwarding(ctx context.Context) error {
	c.mu.Lock()
	if !c.connected || c.sshClient == nil {
		c.mu.Unlock()
		return fmt.Errorf("not connected")
	}
	if c.listener != nil {
		c.mu.Unlock()
		return fmt.Errorf("port forwarding already started")
	}
	c.mu.Unlock()

	// Listen on local port
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", c.localPort))
	if err != nil {
		return fmt.Errorf("failed to listen on local port %d: %w", c.localPort, err)
	}

	c.mu.Lock()
	c.listener = listener
	c.mu.Unlock()

	// Start accepting connections
	go c.acceptConnections(ctx)

	return nil
}

// acceptConnections handles incoming local connections and forwards them through SSH
func (c *Client) acceptConnections(ctx context.Context) {
	var backoff time.Duration
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closeChan:
			return
		default:
		}

		localConn, err := c.listener.Accept()
		if err != nil {
			select {
			case <-c.closeChan:
				return
			default:
			}
			// Back off so a persistent Accept error (e.g. EMFILE) doesn't
			// busy-spin a core; mirrors the server-side accept loop.
			backoff = nextAcceptErrorBackoff(backoff)
			select {
			case <-ctx.Done():
				return
			case <-c.closeChan:
				return
			case <-time.After(backoff):
			}
			continue
		}
		backoff = 0

		// Handle connection in goroutine
		go c.handleConnection(localConn)
	}
}

// handleConnection forwards a single local connection through the SSH tunnel
func (c *Client) handleConnection(localConn net.Conn) {
	defer func() {
		if err := localConn.Close(); err != nil && !isExpectedCloseError(err) {
			_, _ = fmt.Fprintf(status(), "Failed to close local connection: %v\n", err)
		}
	}()

	c.mu.Lock()
	sshClient := c.sshClient
	c.mu.Unlock()

	if sshClient == nil {
		return
	}

	// Open a channel to the node's REST API through the SSH connection.
	remoteConn, err := sshClient.Dial("tcp", forwardedAPIAddress)
	if err != nil {
		_, _ = fmt.Fprintf(status(), "Failed to dial remote port: %v\n", err)
		return
	}
	defer func() {
		if err := remoteConn.Close(); err != nil && !isExpectedCloseError(err) {
			_, _ = fmt.Fprintf(status(), "Failed to close remote connection: %v\n", err)
		}
	}()

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(remoteConn, localConn)
		// Errors are expected when connection closes normally
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(localConn, remoteConn)
		// Errors are expected when connection closes normally
	}()

	wg.Wait()
}

// isExpectedCloseError returns true for errors that are normal during shutdown
// (e.g., EOF or a closed network connection when the SSH client is torn down
// before per-connection cleanup runs). The text fallback covers SSH-library
// errors that embed the net string without wrapping net.ErrClosed.
func isExpectedCloseError(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

// Close closes the SSH connection and stops port forwarding
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
	if c.listener != nil {
		if err := c.listener.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close listener: %w", err))
		}
		c.listener = nil
	}

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

// CheckConnection actively tests the SSH connection by sending a keepalive
func (c *Client) CheckConnection() error {
	c.mu.Lock()
	sshClient := c.sshClient
	c.mu.Unlock()

	if sshClient == nil {
		return fmt.Errorf("not connected")
	}

	// Try to send a keepalive request
	_, _, err := sshClient.SendRequest("keepalive@openssh.com", true, nil)
	if err != nil {
		c.mu.Lock()
		c.connected = false
		c.mu.Unlock()
		return fmt.Errorf("connection dead: %w", err)
	}

	return nil
}

// DialSignerAPI opens one context-bounded SSH channel to the loopback signer
// REST port configured for this client. Callers cannot select another remote
// destination through this method.
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

// RequestEnrollment connects as the enrollment user and asks the operator to
// enroll this client's key, with an optional display label. It is a one-shot
// operation: connect, request, receive the acknowledgement, disconnect. On
// success it returns the enrolled key's fingerprint. No credential is
// returned: the key is the credential.
func (c *Client) RequestEnrollment(ctx context.Context, label string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := parseEnrollmentCommand(enrollmentCommandLine(label)); !ok {
		return "", fmt.Errorf("enrollment label must be printable, single-line, and at most %d bytes", maxEnrollmentLabelBytes)
	}
	var clientFingerprint string
	authMethod, agentConn, err := c.authMethod(func(fingerprint string) { clientFingerprint = fingerprint })
	if err != nil {
		return "", err
	}
	if agentConn != nil {
		defer func() { _ = agentConn.Close() }()
	}

	hostKeyCallback, err := c.hostKeyCallback()
	if err != nil {
		return "", err
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
			return "", fmt.Errorf("SSH connection failed: %w (client access accepts %s keys)", err, clientKeyRequirement)
		}
		return "", fmt.Errorf("SSH connection failed: %w", err)
	}
	defer func() { _ = sshClient.Close() }()

	// Open a session channel
	session, err := sshClient.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
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
		return "", fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := session.Start(enrollmentCommandLine(label)); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", fmt.Errorf("failed to start enrollment: %w", err)
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
			return "", ctx.Err()
		}
		return "", fmt.Errorf("failed to read response: %w", err)
	}
	<-stderrDone
	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	// Wait for command to complete
	if err := session.Wait(); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		errMsg := strings.TrimSpace(string(errOutput))
		if errMsg == "" {
			errMsg = strings.TrimSpace(string(output))
		}
		if errMsg != "" {
			return "", fmt.Errorf("%s", errMsg)
		}
		return "", fmt.Errorf("enrollment failed: %w", err)
	}

	fingerprint, ok := strings.CutPrefix(strings.TrimSpace(string(output)), "enrolled ")
	if !ok || fingerprint == "" {
		return "", fmt.Errorf("unexpected enrollment response: %s", quoteClientText(strings.TrimSpace(string(output))))
	}
	if clientFingerprint != "" && fingerprint != clientFingerprint {
		return "", fmt.Errorf("server enrolled %s, but this client authenticated with %s", fingerprint, clientFingerprint)
	}
	return fingerprint, nil
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
// 1. SSH keepalive pings every 15 seconds
// 2. Wait for SSH connection to close (detects server shutdown)
func (c *Client) monitorConnection(ctx context.Context, sshClient *ssh.Client, keepaliveStop *keepaliveStopSignal) {
	// Start keepalive goroutine
	keepaliveDone := make(chan struct{})
	go func() {
		defer close(keepaliveDone)
		defer func() {
			if r := recover(); r != nil {
				_, _ = fmt.Fprintf(status(), "\n[SSH] Keepalive goroutine panic: %v\n", r)
				c.handleDisconnect()
			}
		}()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-keepaliveStop.done():
				return
			case <-ticker.C:
				// Send keepalive request
				_, _, err := sshClient.SendRequest("keepalive@openssh.com", true, nil)
				if err != nil {
					// Connection is dead
					_, _ = fmt.Fprintf(status(), "\n[SSH] Keepalive failed: %v\n", err)
					c.handleDisconnect()
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
			_, _ = fmt.Fprintf(status(), "\n[SSH] Connection closed with error: %v\n", err)
		}
	}

	// Stop keepalive goroutine
	keepaliveStop.stop()
	<-keepaliveDone

	// Handle disconnection
	c.handleDisconnect()
}

// handleDisconnect is called when the connection dies
func (c *Client) handleDisconnect() {
	c.mu.Lock()
	wasConnected := c.connected
	c.connected = false
	callback := c.onDisconnect
	reason := c.disconnectReason
	c.mu.Unlock()

	// Only trigger callback once
	if wasConnected && callback != nil {
		if reason == DisconnectReasonKeyRevoked {
			_, _ = fmt.Fprintln(status(), "\n[SSH] Disconnected: this client's key was revoked by the signer")
		} else {
			_, _ = fmt.Fprintln(status(), "\n[SSH] Connection closed by remote server")
		}
		callback()
	}
}

// dialAndIntercept connects to the SSH server and intercepts global requests
// from the server (the revocation notice) before forwarding them to ssh.NewClient.
func (c *Client) dialAndIntercept(ctx context.Context, network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	sshConn, chans, reqs, err := dialSSHHandshake(ctx, network, addr, config)
	if err != nil {
		return nil, err
	}

	// Intercept global requests: capture server signals, forward the rest
	filteredReqs := make(chan *ssh.Request, 16)
	go func() {
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
	return client, nil
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
