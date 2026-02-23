// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package transport

import (
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// Transport defines the interface for signer client connections.
type Transport interface {
	// Dial establishes the connection.
	Dial() error

	// Close closes the connection.
	Close()

	// SetReadDeadline sets a deadline for read operations.
	SetReadDeadline(d time.Duration)

	// ClearReadDeadline removes any read deadline.
	ClearReadDeadline()

	// WriteJSON sends a JSON message.
	WriteJSON(v interface{}) error

	// ReadMessage reads a raw message.
	ReadMessage() ([]byte, error)

	// SendAndReceive sends a message and waits for response.
	SendAndReceive(msg interface{}, timeout time.Duration) ([]byte, error)

	// WaitForStatus waits for initial status message.
	WaitForStatus(timeout time.Duration) (*protocol.StatusMessage, error)

	// Authenticate handles the IPC authentication handshake.
	Authenticate(passphrase string, timeout time.Duration) error

	// Unlock sends an unlock request.
	Unlock(passphrase string, timeout time.Duration) (*protocol.UnlockResultMessage, error)
}

// Compile-time interface check
var _ Transport = (*IPCClient)(nil)
