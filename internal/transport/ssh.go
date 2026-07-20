// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package transport

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

// SSHAdminClient carries the admin protocol over the SSH admin subsystem.
type SSHAdminClient struct {
	host           string
	port           int
	identityID     string
	token          string
	identityFile   string
	knownHostsPath string

	mu         sync.Mutex
	writeMu    sync.Mutex
	client     *sshtunnel.Client
	stream     io.ReadWriteCloser
	reader     *bufio.Reader
	deadline   time.Time
	dispatcher *dispatcher
}

// NewSSHAdmin creates a new SSH admin transport.
func NewSSHAdmin(host string, port int, token, identityFile, knownHostsPath string) *SSHAdminClient {
	return NewSSHAdminForIdentity(host, port, auth.CurrentProductIdentityID(), token, identityFile, knownHostsPath)
}

// NewSSHAdminForIdentity creates an identity-scoped SSH admin transport.
// Product-facing callers should use NewSSHAdmin, which remains pinned to the
// current product identity.
func NewSSHAdminForIdentity(host string, port int, identityID, token, identityFile, knownHostsPath string) *SSHAdminClient {
	return &SSHAdminClient{
		host:           host,
		port:           port,
		identityID:     identityID,
		token:          token,
		identityFile:   identityFile,
		knownHostsPath: knownHostsPath,
	}
}

// Dial connects to the remote SSH server and opens the admin subsystem.
func (c *SSHAdminClient) Dial() error {
	return c.DialWithContext(context.Background())
}

// DialWithContext connects to the remote SSH server and opens the admin
// subsystem using the caller's context for the SSH handshake.
func (c *SSHAdminClient) DialWithContext(ctx context.Context) error {
	client := sshtunnel.NewClient(c.host, c.port, 0, 0, c.identityFile, c.knownHostsPath)
	client.SetIdentityID(c.identityID)
	client.SetAPIToken(c.token)
	if err := client.ConnectWithKey(ctx); err != nil {
		return fmt.Errorf("SSH connection failed: %w", err)
	}

	stream, err := client.OpenSubsystem(sshtunnel.AdminSubsystemName)
	if err != nil {
		_ = client.Close()
		return fmt.Errorf("failed to open SSH admin subsystem: %w", err)
	}

	c.mu.Lock()
	c.client = client
	c.stream = stream
	c.reader = bufio.NewReader(stream)
	c.dispatcher = nil
	c.mu.Unlock()
	return nil
}

// Close closes the subsystem stream and SSH connection.
func (c *SSHAdminClient) Close() {
	c.mu.Lock()
	stream := c.stream
	client := c.client
	c.stream = nil
	c.reader = nil
	c.client = nil
	c.dispatcher = nil
	c.deadline = time.Time{}
	c.mu.Unlock()

	if stream != nil {
		_ = stream.Close()
	} else if client != nil {
		_ = client.Close()
	}
}

// SetReadDeadline sets a deadline for subsequent reads. SSH subsystem streams do
// not expose socket deadlines, so timeout expiry is treated as fatal and the
// connection is closed to unblock the pending read.
func (c *SSHAdminClient) SetReadDeadline(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d <= 0 {
		c.deadline = time.Time{}
		return
	}
	c.deadline = time.Now().Add(d)
}

// ClearReadDeadline removes any read deadline.
func (c *SSHAdminClient) ClearReadDeadline() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = time.Time{}
}

// WriteJSON sends a JSON message over the SSH subsystem.
func (c *SSHAdminClient) WriteJSON(v interface{}) error {
	data, err := protocol.MarshalAdminMessage(v)
	if err != nil {
		return err
	}
	c.mu.Lock()
	stream := c.stream
	c.mu.Unlock()
	if stream == nil {
		return fmt.Errorf("not connected")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return protocol.WriteJSONLine(stream, data)
}

// ReadMessage reads a single line-delimited JSON message.
func (c *SSHAdminClient) ReadMessage() ([]byte, error) {
	c.mu.Lock()
	reader := c.reader
	deadline := c.deadline
	c.mu.Unlock()

	if reader == nil {
		return nil, fmt.Errorf("not connected")
	}
	if deadline.IsZero() {
		return readSSHAdminMessageBlocking(reader)
	}

	type result struct {
		line []byte
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		line, err := readSSHAdminMessageBlocking(reader)
		resultCh <- result{line: line, err: err}
	}()

	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()

	select {
	case res := <-resultCh:
		return res.line, res.err
	case <-timer.C:
		c.Close()
		return nil, fmt.Errorf("read timed out")
	}
}

func readSSHAdminMessageBlocking(reader *bufio.Reader) ([]byte, error) {
	return protocol.ReadJSONLine(reader)
}

// SendAndReceive sends a message and waits for a response.
func (c *SSHAdminClient) SendAndReceive(msg interface{}, timeout time.Duration) ([]byte, error) {
	return c.adminDispatcher().request(msg, timeout)
}

func (c *SSHAdminClient) Notifications() <-chan Notification {
	return c.adminDispatcher().notificationsChan()
}

func (c *SSHAdminClient) LifecycleEvents() <-chan LifecycleEvent {
	return c.adminDispatcher().lifecycleChan()
}

func (c *SSHAdminClient) adminDispatcher() *dispatcher {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dispatcher == nil {
		c.dispatcher = newDispatcher(c)
	}
	return c.dispatcher
}

// WaitForStatus waits for the initial status message from the server.
func (c *SSHAdminClient) WaitForStatus(timeout time.Duration) (*protocol.StatusMessage, error) {
	return waitForStatus(c, timeout)
}

// Authenticate handles the admin authentication handshake.
func (c *SSHAdminClient) Authenticate(passphrase string, timeout time.Duration) error {
	return authenticate(c, passphrase, timeout)
}

// Unlock sends an unlock request and waits for the result.
func (c *SSHAdminClient) Unlock(passphrase string, timeout time.Duration) (*protocol.UnlockResultMessage, error) {
	return unlockWithDispatcher(c.adminDispatcher(), passphrase, timeout)
}

var _ Transport = (*SSHAdminClient)(nil)
