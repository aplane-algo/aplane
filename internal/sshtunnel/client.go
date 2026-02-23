// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package sshtunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
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

// HostKeyApprovalHandler is called when connecting to an unknown SSH server.
// It should display the host and fingerprint to the user and return true if trusted.
type HostKeyApprovalHandler func(host string, fingerprint string) (bool, error)

// Client represents an SSH tunnel client with public key authentication.
type Client struct {
	host       string // remote host
	sshPort    int    // SSH port on remote host
	localPort  int    // local port to forward from (auto-selected)
	remotePort int    // remote port to forward to (Signer's HTTP API)

	sshClient *ssh.Client
	listener  net.Listener
	agentConn net.Conn

	identityFile        string
	knownHostsPath      string
	hostKeyApproval     HostKeyApprovalHandler // Callback for TOFU host key approval
	hostKeyApprovalOnce sync.Once              // Ensure we only prompt once per connection

	// Token for authenticating new key registration
	apiToken string

	mu        sync.Mutex
	connected bool
	closeChan chan struct{}

	// Connection monitoring
	keepaliveStop chan struct{} // Signal to stop keepalive goroutine
	onDisconnect  func()        // Callback when connection dies
}

// NewClient creates a new SSH tunnel client.
// host: remote host address
// sshPort: SSH port on remote host
// localPort: local port for tunnel (auto-selected by caller)
// signerPort: remote Signer REST API port
// identityFile: path to SSH private key (optional; if empty, use SSH agent)
// knownHostsPath: path to known_hosts file
func NewClient(host string, sshPort, localPort, signerPort int, identityFile, knownHostsPath string) *Client {
	return &Client{
		host:           host,
		sshPort:        sshPort,
		localPort:      localPort,
		remotePort:     signerPort,
		identityFile:   identityFile,
		knownHostsPath: knownHostsPath,
		closeChan:      make(chan struct{}),
		keepaliveStop:  make(chan struct{}),
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

// SetAPIToken sets the API token used for authentication.
// The token is passed as the SSH username for 2FA (token + public key).
func (c *Client) SetAPIToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.apiToken = token
}

// ConnectWithKey establishes an SSH connection using 2FA: API token + public key.
// The API token (set via SetAPIToken) is passed as the SSH username.
func (c *Client) ConnectWithKey(ctx context.Context) error {
	c.mu.Lock()
	if c.connected {
		c.mu.Unlock()
		return fmt.Errorf("already connected")
	}
	token := c.apiToken
	c.mu.Unlock()

	if token == "" {
		return fmt.Errorf("API token required (call SetAPIToken first)")
	}

	authMethod, agentConn, err := c.authMethod()
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

	// Single auth method: public key (token is passed as username)
	config := &ssh.ClientConfig{
		User:            token, // API token as username for 2FA
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: hostKeyCallback,
		Timeout:         30 * time.Second,
	}

	// Connect to SSH server
	addr := fmt.Sprintf("%s:%d", c.host, c.sshPort)

	sshClient, err := dialWithContext(ctx, "tcp", addr, config)
	if err != nil {
		if agentConn != nil {
			_ = agentConn.Close()
		}
		return fmt.Errorf("SSH connection failed: %w", err)
	}

	c.mu.Lock()
	c.sshClient = sshClient
	c.agentConn = agentConn
	c.connected = true
	// Recreate keepaliveStop channel in case this is a reconnection
	c.keepaliveStop = make(chan struct{})
	c.mu.Unlock()

	// Start connection monitoring
	go c.monitorConnection(ctx, sshClient)

	return nil
}

func (c *Client) authMethod() (ssh.AuthMethod, net.Conn, error) {
	if c.identityFile != "" {
		identityPath := expandUserPath(c.identityFile)
		keyData, err := os.ReadFile(identityPath)
		if err != nil {
			if os.IsNotExist(err) {
				// Auto-generate key if it doesn't exist
				signer, genErr := c.generateIdentityKey(identityPath)
				if genErr != nil {
					// Fall back to SSH agent if key generation fails
					return c.agentAuthMethod()
				}
				return ssh.PublicKeys(signer), nil, nil
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
		return ssh.PublicKeys(signer), nil, nil
	}

	return c.agentAuthMethod()
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

	// Write private key
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
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

	fmt.Printf("\n[SSH] Generated new identity key: %s\n", path)
	fmt.Printf("[SSH] Public key fingerprint: %s\n", ssh.FingerprintSHA256(sshPubKey))
	fmt.Printf("[SSH] Public key (for authorized_keys):\n%s\n", string(authorizedKey))

	return signer, nil
}

func (c *Client) agentAuthMethod() (ssh.AuthMethod, net.Conn, error) {
	agentSock := os.Getenv("SSH_AUTH_SOCK")
	if agentSock == "" {
		return nil, nil, fmt.Errorf("no SSH identity file configured and SSH_AUTH_SOCK is not set")
	}

	conn, err := net.Dial("unix", agentSock)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to SSH agent: %w", err)
	}

	agentClient := agent.NewClient(conn)
	return ssh.PublicKeysCallback(agentClient.Signers), conn, nil
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
			return nil, fmt.Errorf("failed to load known_hosts %s: %w", knownHostsPath, err)
		}
		existingCallback = callback
	}

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
					return fmt.Errorf("SSH host key mismatch for %s (possible MITM attack)", hostname)
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
			return fmt.Errorf("unknown SSH host %s (key %s); add it to %s or set approval handler", hostname, fingerprint, knownHostsPath)
		}

		// Prompt user for approval (only once per connection attempt)
		var approved bool
		var approvalErr error
		c.hostKeyApprovalOnce.Do(func() {
			fmt.Printf("\n[SSH] Unknown host: %s\n", hostname)
			fmt.Printf("[SSH] Host key fingerprint: %s\n", fingerprint)
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
		fmt.Printf("[SSH] Host key saved to %s\n", knownHostsPath)

		return nil
	}, nil
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
				continue
			}
		}

		// Handle connection in goroutine
		go c.handleConnection(localConn)
	}
}

// handleConnection forwards a single local connection through the SSH tunnel
func (c *Client) handleConnection(localConn net.Conn) {
	defer func() {
		if err := localConn.Close(); err != nil {
			fmt.Printf("Failed to close local connection: %v\n", err)
		}
	}()

	c.mu.Lock()
	sshClient := c.sshClient
	c.mu.Unlock()

	if sshClient == nil {
		return
	}

	// Connect to remote port through SSH tunnel
	remoteAddr := fmt.Sprintf("127.0.0.1:%d", c.remotePort)
	remoteConn, err := sshClient.Dial("tcp", remoteAddr)
	if err != nil {
		fmt.Printf("Failed to dial remote port: %v\n", err)
		return
	}
	defer func() {
		if err := remoteConn.Close(); err != nil {
			fmt.Printf("Failed to close remote connection: %v\n", err)
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

	// Stop keepalive monitoring
	select {
	case <-c.keepaliveStop:
		// Already stopped
	default:
		close(c.keepaliveStop)
	}

	c.mu.Unlock()

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

// RequestToken connects to the SSH server and requests a token via the exec channel.
// This is a one-shot operation: connect, request, receive token, disconnect.
// The identityID is typically "default".
func (c *Client) RequestToken(ctx context.Context, identityID string) (string, error) {
	authMethod, agentConn, err := c.authMethod()
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

	// Use special username for token provisioning
	username := "request-token:" + identityID

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: hostKeyCallback,
		Timeout:         30 * time.Second,
	}

	// Connect to SSH server
	addr := fmt.Sprintf("%s:%d", c.host, c.sshPort)
	sshClient, err := dialWithContext(ctx, "tcp", addr, config)
	if err != nil {
		return "", fmt.Errorf("SSH connection failed: %w", err)
	}
	defer func() { _ = sshClient.Close() }()

	// Open a session channel
	session, err := sshClient.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer func() { _ = session.Close() }()

	// Set up pipes for output
	stdout, err := session.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Run the "provision" command
	if err := session.Start("provision"); err != nil {
		return "", fmt.Errorf("failed to start provisioning: %w", err)
	}

	// Read stdout (should contain the token on success)
	output, err := io.ReadAll(stdout)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Read stderr for error message
	errOutput, _ := io.ReadAll(stderr)

	// Wait for command to complete
	if err := session.Wait(); err != nil {
		errMsg := strings.TrimSpace(string(errOutput))
		if errMsg == "" {
			errMsg = strings.TrimSpace(string(output))
		}
		if errMsg != "" {
			return "", fmt.Errorf("%s", errMsg)
		}
		return "", fmt.Errorf("provisioning failed: %w", err)
	}

	// Success - return the token (trimmed)
	token := strings.TrimSpace(string(output))
	if token == "" {
		return "", fmt.Errorf("empty token received")
	}

	return token, nil
}

// monitorConnection monitors the SSH connection and detects when it dies
// It runs two detection mechanisms:
// 1. SSH keepalive pings every 15 seconds
// 2. Wait for SSH connection to close (detects server shutdown)
func (c *Client) monitorConnection(ctx context.Context, sshClient *ssh.Client) {
	// Start keepalive goroutine
	keepaliveDone := make(chan struct{})
	go func() {
		defer close(keepaliveDone)
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("\n[SSH] Keepalive goroutine panic: %v\n", r)
				c.handleDisconnect()
			}
		}()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-c.keepaliveStop:
				return
			case <-ticker.C:
				// Send keepalive request
				_, _, err := sshClient.SendRequest("keepalive@openssh.com", true, nil)
				if err != nil {
					// Connection is dead
					fmt.Printf("\n[SSH] Keepalive failed: %v\n", err)
					c.handleDisconnect()
					return
				}
			}
		}
	}()

	// Wait for SSH connection to close (blocks until connection dies)
	// This detects server-side shutdowns
	if err := sshClient.Wait(); err != nil {
		fmt.Printf("\n[SSH] Connection closed with error: %v\n", err)
	}

	// Stop keepalive goroutine
	select {
	case <-c.keepaliveStop:
		// Already stopped
	default:
		close(c.keepaliveStop)
	}
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
	c.mu.Unlock()

	// Only trigger callback once
	if wasConnected && callback != nil {
		fmt.Println("\n[SSH] Connection closed by remote server")
		callback()
	}
}

// dialWithContext connects to SSH server with context support
func dialWithContext(ctx context.Context, network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	d := net.Dialer{Timeout: config.Timeout}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	// Wrap in a context-cancellable connection
	ctxConn := &contextConn{Conn: conn, ctx: ctx}

	c, chans, reqs, err := ssh.NewClientConn(ctxConn, addr, config)
	if err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			return nil, fmt.Errorf("failed to establish SSH connection: %w (and failed to close connection: %v)", err, closeErr)
		}
		return nil, err
	}

	client := ssh.NewClient(c, chans, reqs)
	return client, nil
}

// contextConn wraps net.Conn to support context cancellation
type contextConn struct {
	net.Conn
	ctx context.Context
}

func (c *contextConn) Read(b []byte) (n int, err error) {
	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	default:
		return c.Conn.Read(b)
	}
}

func (c *contextConn) Write(b []byte) (n int, err error) {
	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	default:
		return c.Conn.Write(b)
	}
}
