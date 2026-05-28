// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminproto

// AdminConn is the transport contract for a framed admin protocol connection.
type AdminConn interface {
	ReadMessage() ([]byte, error)
	WriteMessage(data []byte) error
	RemoteAddr() string
	Close() error
}
