// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package transport

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

type adminProtocolConn interface {
	WriteJSON(v interface{}) error
	ReadMessage() ([]byte, error)
	SetReadDeadline(d time.Duration)
	ClearReadDeadline()
}

func waitForStatus(conn adminProtocolConn, timeout time.Duration) (*protocol.StatusMessage, error) {
	conn.SetReadDeadline(timeout)
	defer conn.ClearReadDeadline()

	message, err := conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("failed to receive status: %w", err)
	}

	var status protocol.StatusMessage
	if err := json.Unmarshal(message, &status); err != nil {
		return nil, fmt.Errorf("failed to parse status: %w", err)
	}

	return &status, nil
}

func authenticate(conn adminProtocolConn, passphrase string, timeout time.Duration) error {
	conn.SetReadDeadline(timeout)
	defer conn.ClearReadDeadline()

	for {
		message, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("failed to receive auth_required: %w", err)
		}

		base, err := protocol.ParseAdminBaseMessage(message)
		if err != nil {
			return fmt.Errorf("failed to parse auth_required: %w", err)
		}
		if base.Type == protocol.MsgTypeClientExists {
			if err := conn.WriteJSON(protocol.DisplaceConfirmMessage{
				BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeDisplaceConfirm},
			}); err != nil {
				return fmt.Errorf("failed to confirm client displacement: %w", err)
			}
			continue
		}
		if base.Type == protocol.MsgTypeError {
			var errMsg protocol.ErrorMessage
			if err := json.Unmarshal(message, &errMsg); err != nil {
				return fmt.Errorf("server rejected auth handshake")
			}
			if errMsg.Error != "" {
				return fmt.Errorf("server rejected auth handshake: %s", errMsg.Error)
			}
			return fmt.Errorf("server rejected auth handshake")
		}
		if base.Type != protocol.MsgTypeAuthRequired {
			return fmt.Errorf("expected auth_required message, got: %s", base.Type)
		}
		break
	}

	authMsg := protocol.AuthMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAuth},
		Passphrase:  protocol.NewSensitiveBytes(passphrase),
	}
	if err := conn.WriteJSON(authMsg); err != nil {
		return fmt.Errorf("failed to send auth message: %w", err)
	}

	resultMsg, err := conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to receive auth_result: %w", err)
	}

	resultBase, err := protocol.ParseAdminBaseMessage(resultMsg)
	if err != nil {
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

func unlockWithDispatcher(dispatcher *dispatcher, passphrase string, timeout time.Duration) (*protocol.UnlockResultMessage, error) {
	msg := protocol.UnlockMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeUnlock,
			ID:   fmt.Sprintf("unlock-%d", time.Now().UnixNano()),
		},
		Passphrase: protocol.NewSensitiveBytes(passphrase),
	}

	response, err := dispatcher.request(msg, timeout)
	if err != nil {
		return nil, err
	}

	var result protocol.UnlockResultMessage
	if err := json.Unmarshal(response, &result); err != nil {
		return nil, fmt.Errorf("failed to parse unlock result: %w", err)
	}

	return &result, nil
}

func messageID(msg interface{}) (string, error) {
	data, err := protocol.MarshalAdminMessage(msg)
	if err != nil {
		return "", fmt.Errorf("failed to encode request envelope: %w", err)
	}
	return rawMessageID(data)
}

func rawMessageID(data []byte) (string, error) {
	base, err := parseBaseMessage(data)
	if err != nil {
		return "", fmt.Errorf("failed to parse protocol envelope: %w", err)
	}
	return base.ID, nil
}

func parseBaseMessage(data []byte) (protocol.BaseMessage, error) {
	return protocol.ParseAdminBaseMessage(data)
}
