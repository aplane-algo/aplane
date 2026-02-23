// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package transport

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// IPCClient is a Unix socket client for Signer connections.
type IPCClient struct {
	conn       net.Conn
	socketPath string
	reader     *bufio.Reader
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
	c.conn = conn
	c.reader = bufio.NewReader(conn)
	return nil
}

// Close closes the IPC connection.
func (c *IPCClient) Close() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

// SetReadDeadline sets a deadline for read operations.
func (c *IPCClient) SetReadDeadline(d time.Duration) {
	if c.conn != nil {
		_ = c.conn.SetReadDeadline(time.Now().Add(d))
	}
}

// ClearReadDeadline removes any read deadline.
func (c *IPCClient) ClearReadDeadline() {
	if c.conn != nil {
		_ = c.conn.SetReadDeadline(time.Time{})
	}
}

// WriteJSON sends a JSON message over the socket.
// Each message is a single line terminated by newline.
func (c *IPCClient) WriteJSON(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = c.conn.Write(data)
	return err
}

// ReadMessage reads a line-delimited JSON message from the socket.
func (c *IPCClient) ReadMessage() ([]byte, error) {
	line, err := c.reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	// Trim the newline
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	return line, nil
}

// SendAndReceive sends a JSON message and waits for a response.
func (c *IPCClient) SendAndReceive(msg interface{}, timeout time.Duration) ([]byte, error) {
	if err := c.WriteJSON(msg); err != nil {
		return nil, err
	}
	c.SetReadDeadline(timeout)
	return c.ReadMessage()
}

// WaitForStatus waits for the initial status message from the server.
func (c *IPCClient) WaitForStatus(timeout time.Duration) (*protocol.StatusMessage, error) {
	c.SetReadDeadline(timeout)
	message, err := c.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("failed to receive status: %w", err)
	}

	var status protocol.StatusMessage
	if err := json.Unmarshal(message, &status); err != nil {
		return nil, fmt.Errorf("failed to parse status: %w", err)
	}

	return &status, nil
}

// Authenticate handles the IPC authentication handshake.
// It reads the auth_required message, sends the auth message with passphrase,
// and waits for the auth_result.
func (c *IPCClient) Authenticate(passphrase string, timeout time.Duration) error {
	c.SetReadDeadline(timeout)

	// Read the auth_required message
	message, err := c.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to receive auth_required: %w", err)
	}

	var base protocol.BaseMessage
	if err := json.Unmarshal(message, &base); err != nil {
		return fmt.Errorf("failed to parse auth_required: %w", err)
	}

	if base.Type != protocol.MsgTypeAuthRequired {
		return fmt.Errorf("expected auth_required message, got: %s", base.Type)
	}

	// Send auth message with passphrase
	authMsg := protocol.AuthMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeAuth,
		},
		Passphrase: passphrase,
	}
	if err := c.WriteJSON(authMsg); err != nil {
		return fmt.Errorf("failed to send auth message: %w", err)
	}

	// Read auth_result
	resultMsg, err := c.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to receive auth_result: %w", err)
	}

	// First check the message type
	var resultBase protocol.BaseMessage
	if err := json.Unmarshal(resultMsg, &resultBase); err != nil {
		return fmt.Errorf("failed to parse auth_result: %w", err)
	}
	if resultBase.Type != protocol.MsgTypeAuthResult {
		return fmt.Errorf("expected auth_result message, got: %s", resultBase.Type)
	}

	var authResult protocol.AuthResultMessage
	if err := json.Unmarshal(resultMsg, &authResult); err != nil {
		return fmt.Errorf("failed to parse auth_result: %w", err)
	}

	if !authResult.Success {
		return fmt.Errorf("authentication failed: %s", authResult.Error)
	}

	return nil
}

// Unlock sends an unlock request and waits for the result.
func (c *IPCClient) Unlock(passphrase string, timeout time.Duration) (*protocol.UnlockResultMessage, error) {
	msg := protocol.UnlockMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeUnlock,
			ID:   fmt.Sprintf("unlock-%d", time.Now().UnixNano()),
		},
		Passphrase: passphrase,
	}

	response, err := c.SendAndReceive(msg, timeout)
	if err != nil {
		return nil, err
	}

	var result protocol.UnlockResultMessage
	if err := json.Unmarshal(response, &result); err != nil {
		return nil, fmt.Errorf("failed to parse unlock result: %w", err)
	}

	return &result, nil
}
