// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package transport

import (
	"errors"
	"testing"
)

func TestErrors(t *testing.T) {
	// Test that sentinel errors are properly defined
	if !errors.Is(ErrAlreadyConnected, ErrAlreadyConnected) {
		t.Error("ErrAlreadyConnected is not itself")
	}
	if !errors.Is(ErrUnauthorized, ErrUnauthorized) {
		t.Error("ErrUnauthorized is not itself")
	}

	// Test error messages
	if ErrAlreadyConnected.Error() == "" {
		t.Error("ErrAlreadyConnected has empty message")
	}
	if ErrUnauthorized.Error() == "" {
		t.Error("ErrUnauthorized has empty message")
	}
}

func TestNewIPC(t *testing.T) {
	client := NewIPC("/tmp/test.sock")
	if client == nil {
		t.Fatal("NewIPC returned nil")
	}
	if client.socketPath != "/tmp/test.sock" {
		t.Errorf("socketPath = %q, want %q", client.socketPath, "/tmp/test.sock")
	}
}

func TestIPCCloseNilConn(t *testing.T) {
	// Close should not panic when conn is nil
	client := NewIPC("/tmp/test.sock")
	client.Close() // Should not panic
}

func TestIPCSetDeadlineNilConn(t *testing.T) {
	// SetReadDeadline and ClearReadDeadline should not panic when conn is nil
	client := NewIPC("/tmp/test.sock")
	client.SetReadDeadline(5)  // Should not panic
	client.ClearReadDeadline() // Should not panic
}

func TestTransportInterface(t *testing.T) {
	// Verify IPC client implements Transport interface
	var _ Transport = (*IPCClient)(nil)
}
