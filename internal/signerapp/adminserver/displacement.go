// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"github.com/aplane-algo/aplane/internal/adminproto"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// OfferDisplacement sends a client_exists message to newConn and waits for a
// displace_confirm response. Confirmation only authorizes replacement; the
// old active session remains the owner until the caller promotes the new
// session and then calls DisplaceSession.
func OfferDisplacement(active *Session, newConn adminproto.AdminConn, timeout time.Duration) (confirmed bool, displaced bool) {
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

	return true, active != nil
}

// DisplaceSession notifies and closes a session after its replacement has
// already become active. This ordering preserves the invariant that an
// unlocked identity always has an owner session whose disconnect can clean up.
func DisplaceSession(active *Session) {
	if active == nil {
		return
	}
	active.mu.Lock()
	if active.state != StateClosed {
		active.state = StateDisplacing
	}
	active.mu.Unlock()

	displacedMsg := protocol.DisplacedMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeDisplaced},
		Reason:      "Displaced by another apadmin client",
	}
	_ = active.WriteJSON(displacedMsg)
	_ = active.Close()
}

func writeJSONMessage(conn adminproto.AdminConn, v interface{}) error {
	data, err := protocol.MarshalAdminMessage(v)
	if err != nil {
		return err
	}
	return conn.WriteMessage(data)
}
