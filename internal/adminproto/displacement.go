// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminproto

import (
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// OfferDisplacement sends a client_exists message to newConn and waits for a
// displace_confirm response. If confirmed, it clears and closes active.
func OfferDisplacement(identityID string, manager *SessionManager, active *Session, newConn AdminConn, timeout time.Duration) (confirmed bool, displaced bool) {
	reject := func() (bool, bool) {
		_ = newConn.Close()
		return false, false
	}

	existsMsg := protocol.ClientExistsMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeClientExists},
	}
	if err := writeJSONMessage(newConn, existsMsg); err != nil {
		return reject()
	}

	type response struct {
		line []byte
		err  error
	}
	responseCh := make(chan response, 1)
	go func() {
		line, err := newConn.ReadMessage()
		responseCh <- response{line: line, err: err}
	}()

	var line []byte
	select {
	case resp := <-responseCh:
		if resp.err != nil {
			return reject()
		}
		line = resp.line
	case <-time.After(timeout):
		return reject()
	}

	base, err := protocol.ParseAdminBaseMessage(line)
	if err != nil {
		return reject()
	}
	if base.Type != protocol.MsgTypeDisplaceConfirm {
		return reject()
	}

	if active != nil {
		if manager != nil {
			_ = manager.ClearActive(identityID, active)
		}
		displacedMsg := protocol.DisplacedMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeDisplaced},
			Reason:      "Displaced by another apadmin client",
		}
		_ = active.WriteJSON(displacedMsg)
		_ = active.Close()
		return true, true
	}

	return true, false
}

func writeJSONMessage(conn AdminConn, v interface{}) error {
	data, err := protocol.MarshalAdminMessage(v)
	if err != nil {
		return err
	}
	return conn.WriteMessage(data)
}
