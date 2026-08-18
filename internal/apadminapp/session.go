// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package apadminapp owns noninteractive workflows executed by apadmin against
// a running apsigner. Command-line parsing and transport selection remain in
// cmd/apadmin; wire DTOs and framing remain in protocol and transport.
package apadminapp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

const (
	DefaultTimeout      = 30 * time.Second
	BackupCommitTimeout = 30 * time.Minute
)

// AuthMode states whether a workflow may change the runtime's locked state.
type AuthMode uint8

const (
	// AuthReadOnly authenticates with auth_only and does not unlock. The server
	// treats it as a non-owning observer and enforces an explicit public-read
	// request allowlist.
	AuthReadOnly AuthMode = iota
	// AuthUnlock authenticates normally and unlocks only when status reports a
	// locked runtime.
	AuthUnlock
)

// Session is the transport-neutral admin session used by batch workflows.
// Both local IPC and strict-known-host SSH transports implement it.
type Session interface {
	Dial() error
	Close()
	Authenticate(string, time.Duration) error
	AuthenticateOnly(string, time.Duration) error
	WaitForStatus(time.Duration) (*protocol.StatusMessage, error)
	Unlock(string, time.Duration) (*protocol.UnlockResultMessage, error)
	SendAndReceive(interface{}, time.Duration) ([]byte, error)
}

// Client is an authenticated request client. Close must be called after a
// successful Open.
type Client struct {
	session Session
	timeout time.Duration
}

// Open dials and authenticates a batch session using the requested lock-state
// behavior. It closes the transport on every failed setup path.
func Open(session Session, passphrase []byte, mode AuthMode) (*Client, error) {
	if session == nil {
		return nil, fmt.Errorf("admin session is required")
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("admin passphrase cannot be empty")
	}
	if err := session.Dial(); err != nil {
		return nil, fmt.Errorf("connect to apsigner admin service: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			session.Close()
		}
	}()

	secret := string(passphrase)
	switch mode {
	case AuthReadOnly:
		if err := session.AuthenticateOnly(secret, DefaultTimeout); err != nil {
			return nil, fmt.Errorf("authenticate admin session: %w", err)
		}
	case AuthUnlock:
		if err := session.Authenticate(secret, DefaultTimeout); err != nil {
			return nil, fmt.Errorf("authenticate admin session: %w", err)
		}
		status, err := session.WaitForStatus(DefaultTimeout)
		if err != nil {
			return nil, fmt.Errorf("read signer status: %w", err)
		}
		if status.State == "locked" {
			result, err := session.Unlock(secret, DefaultTimeout)
			if err != nil {
				return nil, protocol.WithCode(protocol.ErrCodeUnlockFailed, fmt.Errorf("unlock signer: %w", err))
			}
			if !result.Success {
				code := result.Code
				if code == "" {
					code = protocol.ErrCodeUnlockFailed
				}
				detail := result.Error
				if detail == "" {
					detail = "operation failed"
				}
				return nil, protocol.WithCode(code, fmt.Errorf("unlock signer: %s", detail))
			}
		}
	default:
		return nil, fmt.Errorf("unsupported admin authentication mode %d", mode)
	}

	ok = true
	return &Client{session: session, timeout: DefaultTimeout}, nil
}

// Close closes the underlying session.
func (c *Client) Close() {
	if c != nil && c.session != nil {
		c.session.Close()
	}
}

// Request sends one correlated admin request with the default timeout.
func (c *Client) Request(message, result any) error {
	return c.RequestWithTimeout(message, result, c.timeout)
}

// RequestWithTimeout sends one correlated request, rejects protocol error
// envelopes while preserving their structured code, and decodes the expected
// response.
func (c *Client) RequestWithTimeout(message, result any, timeout time.Duration) error {
	if c == nil || c.session == nil {
		return fmt.Errorf("admin client is not open")
	}
	raw, err := c.session.SendAndReceive(message, timeout)
	if err != nil {
		return err
	}
	base, err := protocol.ParseAdminBaseMessage(raw)
	if err != nil {
		return fmt.Errorf("decode admin response envelope: %w", err)
	}
	if base.Type == protocol.MsgTypeError {
		var response protocol.ErrorMessage
		if err := json.Unmarshal(raw, &response); err != nil {
			return fmt.Errorf("decode admin error response: %w", err)
		}
		code := response.Code
		if code == "" {
			code = protocol.IPCErrorCode(response.Error)
		}
		return protocol.WithCode(code, fmt.Errorf("%s", response.Error))
	}
	if err := json.Unmarshal(raw, result); err != nil {
		return fmt.Errorf("decode admin response: %w", err)
	}
	return nil
}
