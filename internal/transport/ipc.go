// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package transport

import (
	"bufio"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// IPCClient is a Unix socket client for Signer connections.
type IPCClient struct {
	mu         sync.Mutex
	writeMu    sync.Mutex
	conn       net.Conn
	socketPath string
	reader     *bufio.Reader
	dispatcher *dispatcher
}

// NewIPC creates a new IPC client (not yet connected).
func NewIPC(socketPath string) *IPCClient {
	return &IPCClient{
		socketPath: socketPath,
	}
}

// Dial connects to the Signer Unix socket.
func (c *IPCClient) Dial() error {
	conn, err := net.Dial("unix", c.socketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to IPC socket: %w", err)
	}
	c.mu.Lock()
	c.conn = conn
	c.reader = bufio.NewReader(conn)
	c.dispatcher = nil
	c.mu.Unlock()
	return nil
}

// Close closes the IPC connection.
func (c *IPCClient) Close() {
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.reader = nil
	c.dispatcher = nil
	c.mu.Unlock()

	if conn != nil {
		_ = conn.Close()
	}
}

// SetReadDeadline sets a deadline for read operations.
func (c *IPCClient) SetReadDeadline(d time.Duration) {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		_ = conn.SetReadDeadline(time.Now().Add(d))
	}
}

// ClearReadDeadline removes any read deadline.
func (c *IPCClient) ClearReadDeadline() {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		_ = conn.SetReadDeadline(time.Time{})
	}
}

// WriteJSON sends a JSON message over the socket.
// Each message is a single line terminated by newline.
func (c *IPCClient) WriteJSON(v interface{}) error {
	data, err := protocol.MarshalAdminMessage(v)
	if err != nil {
		return err
	}
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("not connected")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return protocol.WriteJSONLine(conn, data)
}

// ReadMessage reads a line-delimited JSON message from the socket.
func (c *IPCClient) ReadMessage() ([]byte, error) {
	c.mu.Lock()
	reader := c.reader
	c.mu.Unlock()
	if reader == nil {
		return nil, fmt.Errorf("not connected")
	}
	return protocol.ReadJSONLine(reader)
}

// SendAndReceive sends a JSON message and waits for a response.
func (c *IPCClient) SendAndReceive(msg interface{}, timeout time.Duration) ([]byte, error) {
	return c.adminDispatcher().request(msg, timeout)
}

func (c *IPCClient) Notifications() <-chan Notification {
	return c.adminDispatcher().notificationsChan()
}

func (c *IPCClient) LifecycleEvents() <-chan LifecycleEvent {
	return c.adminDispatcher().lifecycleChan()
}

func (c *IPCClient) adminDispatcher() *dispatcher {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dispatcher == nil {
		c.dispatcher = newDispatcher(c)
	}
	return c.dispatcher
}

// WaitForStatus waits for the initial status message from the server.
func (c *IPCClient) WaitForStatus(timeout time.Duration) (*protocol.StatusMessage, error) {
	return waitForStatus(c, timeout)
}

// Authenticate handles the IPC authentication handshake.
// It reads the auth_required message, sends the auth message with passphrase,
// and waits for the auth_result.
func (c *IPCClient) Authenticate(passphrase string, timeout time.Duration) error {
	return authenticate(c, passphrase, timeout)
}

// AuthenticateOnly verifies and binds the admin session without transitioning
// a locked identity to unlocked. It is intended for bound-runtime reads; it
// does not create a read-only session capability. Subsequent requests remain
// subject to their normal authorization and runtime-state gates.
func (c *IPCClient) AuthenticateOnly(passphrase string, timeout time.Duration) error {
	return authenticateOnly(c, passphrase, timeout)
}

// Unlock sends an unlock request and waits for the result.
func (c *IPCClient) Unlock(passphrase string, timeout time.Duration) (*protocol.UnlockResultMessage, error) {
	return unlockWithDispatcher(c.adminDispatcher(), passphrase, timeout)
}
