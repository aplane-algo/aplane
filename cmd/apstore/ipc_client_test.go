// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestCmdTemplatesReportsIPCUnavailableWithoutDaemon(t *testing.T) {
	oldConfig := config
	defer func() { config = oldConfig }()

	config.IPCPath = filepath.Join(t.TempDir(), "missing.sock")
	err := cmdTemplates()
	if err == nil {
		t.Fatal("cmdTemplates() error = nil, want IPC connection failure")
	}
	if !strings.Contains(err.Error(), "failed to connect to IPC socket") {
		t.Fatalf("cmdTemplates() error = %v, want IPC connection context", err)
	}
}

func TestCmdTemplatesReportsIPCAuthenticationFailure(t *testing.T) {
	oldConfig := config
	defer func() { config = oldConfig }()
	t.Setenv("TEST_PASSPHRASE", "wrong-passphrase")

	socketPath, done := startApstoreIPCTestServer(t, func(reader *bufio.Reader, conn net.Conn) error {
		if err := writeAdminTestMessage(conn, protocol.BaseMessage{Type: protocol.MsgTypeAuthRequired}); err != nil {
			return err
		}
		authLine, err := protocol.ReadJSONLine(reader)
		if err != nil {
			return err
		}
		var authMsg protocol.AuthMessage
		if err := json.Unmarshal(authLine, &authMsg); err != nil {
			return err
		}
		if string(authMsg.Passphrase) != "wrong-passphrase" {
			return fmt.Errorf("auth passphrase = %q, want wrong-passphrase", string(authMsg.Passphrase))
		}
		return writeAdminTestMessage(conn, protocol.AuthResultMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAuthResult},
			Success:     false,
			Code:        protocol.ErrCodeAuthenticationFailed,
			Error:       "invalid passphrase",
		})
	})
	config.IPCPath = socketPath

	err := cmdTemplates()
	if err == nil {
		t.Fatal("cmdTemplates() error = nil, want authentication failure")
	}
	if !strings.Contains(err.Error(), "authentication failed: invalid passphrase") {
		t.Fatalf("cmdTemplates() error = %v, want authentication failure context", err)
	}
	waitApstoreIPCTestServer(t, done)
}

func TestCmdTemplatesReportsLockedSignerUnlockFailure(t *testing.T) {
	oldConfig := config
	defer func() { config = oldConfig }()
	t.Setenv("TEST_PASSPHRASE", "wrong-unlock-passphrase")

	socketPath, done := startApstoreIPCTestServer(t, func(reader *bufio.Reader, conn net.Conn) error {
		if err := writeAdminTestMessage(conn, protocol.BaseMessage{Type: protocol.MsgTypeAuthRequired}); err != nil {
			return err
		}
		authLine, err := protocol.ReadJSONLine(reader)
		if err != nil {
			return err
		}
		var authMsg protocol.AuthMessage
		if err := json.Unmarshal(authLine, &authMsg); err != nil {
			return err
		}
		if string(authMsg.Passphrase) != "wrong-unlock-passphrase" {
			return fmt.Errorf("auth passphrase = %q, want wrong-unlock-passphrase", string(authMsg.Passphrase))
		}
		if err := writeAdminTestMessage(conn, protocol.AuthResultMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAuthResult},
			Success:     true,
		}); err != nil {
			return err
		}
		if err := writeAdminTestMessage(conn, protocol.StatusMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeStatus},
			State:       "locked",
		}); err != nil {
			return err
		}
		unlockLine, err := protocol.ReadJSONLine(reader)
		if err != nil {
			return err
		}
		var unlockMsg protocol.UnlockMessage
		if err := json.Unmarshal(unlockLine, &unlockMsg); err != nil {
			return err
		}
		if string(unlockMsg.Passphrase) != "wrong-unlock-passphrase" {
			return fmt.Errorf("unlock passphrase = %q, want wrong-unlock-passphrase", string(unlockMsg.Passphrase))
		}
		return writeAdminTestMessage(conn, protocol.UnlockResultMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeUnlockResult, ID: unlockMsg.ID},
			Success:     false,
			Code:        protocol.ErrCodeInvalidPassphrase,
			Error:       "invalid passphrase",
		})
	})
	config.IPCPath = socketPath

	err := cmdTemplates()
	if err == nil {
		t.Fatal("cmdTemplates() error = nil, want locked signer unlock failure")
	}
	if !strings.Contains(err.Error(), "signer is locked and could not unlock: invalid passphrase") {
		t.Fatalf("cmdTemplates() error = %v, want locked signer unlock context", err)
	}
	waitApstoreIPCTestServer(t, done)
}
