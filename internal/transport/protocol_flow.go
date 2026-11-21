// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package transport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// adminProtocolConn carries admin frames: what the dispatcher needs.
type adminProtocolConn interface {
	WriteJSON(v interface{}) error
	ReadMessage() ([]byte, error)
}

// handshakeConn is an adminProtocolConn whose reads can be bounded, for the
// status wait and login that run before the dispatcher reads.
type handshakeConn interface {
	adminProtocolConn
	SetReadDeadline(d time.Duration)
	ClearReadDeadline()
}

func waitForStatus(conn handshakeConn, timeout time.Duration) (*protocol.StatusMessage, error) {
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

// authenticateWithMode runs the login handshake. The auth message carries its
// own copy of the passphrase, zeroed once the handshake ends, and the frame
// writer zeroes the encoding; the caller zeroes its own buffer.
func authenticateWithMode(conn handshakeConn, passphrase []byte, timeout time.Duration, only bool) error {
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
			code := errMsg.Code
			if errMsg.Error != "" {
				return protocol.WithCode(code, fmt.Errorf("server rejected auth handshake: %s", errMsg.Error))
			}
			return protocol.WithCode(code, fmt.Errorf("server rejected auth handshake"))
		}
		if base.Type != protocol.MsgTypeAuthRequired {
			return fmt.Errorf("expected auth_required message, got: %s", base.Type)
		}
		break
	}

	authType := protocol.MsgTypeAuth
	if only {
		authType = protocol.MsgTypeAuthOnly
	}
	authMsg := protocol.AuthMessage{
		BaseMessage:     protocol.BaseMessage{Type: authType},
		Passphrase:      protocol.SensitiveBytes(bytes.Clone(passphrase)),
		ProtocolVersion: protocol.AdminProtocolVersion,
	}
	defer authMsg.Passphrase.Zero()
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
		return protocol.WithCode(authResult.Code, fmt.Errorf("authentication failed: %s", authResult.Error))
	}

	return nil
}

// unlockWithDispatcher sends an unlock request carrying its own copy of the
// passphrase, zeroed once the request ends; the caller zeroes its own buffer.
func unlockWithDispatcher(dispatcher *dispatcher, passphrase []byte, timeout time.Duration) (*protocol.UnlockResultMessage, error) {
	msg := protocol.UnlockMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeUnlock,
			ID:   fmt.Sprintf("unlock-%d", time.Now().UnixNano()),
		},
		Passphrase: protocol.SensitiveBytes(bytes.Clone(passphrase)),
	}
	defer msg.Passphrase.Zero()

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

// writeAdminFrame encodes v as one admin frame, writes it to w, and zeroes
// the encoding, which may carry a passphrase or a recovery phrase.
func writeAdminFrame(w io.Writer, v interface{}) error {
	data, err := protocol.MarshalAdminMessage(v)
	if err != nil {
		return err
	}
	defer protocol.SensitiveBytes(data).Zero()
	return protocol.WriteJSONLine(w, data)
}

// messageID reads the correlation ID of an outgoing request from its
// envelope without encoding it, so a request that carries a passphrase is
// encoded only once, by the zeroing frame writer.
func messageID(msg interface{}) (string, error) {
	identified, ok := msg.(interface{ MessageID() string })
	if !ok {
		return "", fmt.Errorf("request %T has no admin message envelope", msg)
	}
	return identified.MessageID(), nil
}
