// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminproto

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// adminWriteTimeout bounds how long a single admin-protocol write may block on
// a slow or dead client before the connection is treated as failed. Without
// it, a stalled client wedges every daemon-side writer that targets this
// connection (approval prompts, notifications, responses).
const adminWriteTimeout = 30 * time.Second

// StreamAdminConn adapts a line-delimited stream to a transport-neutral admin
// protocol connection. Writes are serialized per connection: the message loop
// and async notifiers (approval prompts, key-change notifications) write
// concurrently to the same stream.
type StreamAdminConn struct {
	closer  io.Closer
	reader  *protocol.FrameReader
	addr    string
	writeMu sync.Mutex
	writer  io.Writer

	writeTimeout time.Duration // 0 means adminWriteTimeout; settable in tests
}

func (c *StreamAdminConn) effectiveWriteTimeout() time.Duration {
	if c.writeTimeout > 0 {
		return c.writeTimeout
	}
	return adminWriteTimeout
}

func NewStreamAdminConn(rw io.ReadWriteCloser, addr string) *StreamAdminConn {
	return &StreamAdminConn{
		closer: rw,
		reader: protocol.NewFrameReader(rw),
		addr:   addr,
		writer: rw,
	}
}

func NewUnixAdminConn(conn net.Conn) *StreamAdminConn {
	var reader *protocol.FrameReader
	if conn != nil {
		reader = protocol.NewFrameReader(conn)
	}
	return NewUnixAdminConnWithReader(conn, reader)
}

// NewUnixAdminConnWithReader reads frames from reader instead of conn.
func NewUnixAdminConnWithReader(conn net.Conn, reader *protocol.FrameReader) *StreamAdminConn {
	return &StreamAdminConn{
		closer: conn,
		reader: reader,
		addr:   remoteAddrString(conn),
		writer: conn,
	}
}

func (c *StreamAdminConn) ReadMessage() ([]byte, error) {
	return c.reader.ReadFrame()
}

type readDeadlineSetter interface {
	SetReadDeadline(time.Time) error
}

// SetReadDeadline bounds pending and future reads when the underlying stream
// supports deadlines; otherwise it reports that it cannot.
func (c *StreamAdminConn) SetReadDeadline(t time.Time) error {
	d, ok := c.closer.(readDeadlineSetter)
	if !ok {
		return errors.ErrUnsupported
	}
	return d.SetReadDeadline(t)
}

type writeDeadlineSetter interface {
	SetWriteDeadline(time.Time) error
}

func (c *StreamAdminConn) WriteMessage(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if d, ok := c.writer.(writeDeadlineSetter); ok {
		_ = d.SetWriteDeadline(time.Now().Add(c.effectiveWriteTimeout()))
		err := protocol.WriteJSONLine(c.writer, data)
		_ = d.SetWriteDeadline(time.Time{})
		if err != nil && errors.Is(err, os.ErrDeadlineExceeded) {
			// The frame may be partially written; the stream is unusable.
			_ = c.Close()
		}
		return err
	}

	// Transports without native write deadlines (e.g. SSH channels): force-close
	// the stream if the write stalls, so a dead client surfaces as a write
	// error instead of blocking this connection's writers indefinitely.
	timer := time.AfterFunc(c.effectiveWriteTimeout(), func() { _ = c.Close() })
	defer timer.Stop()
	return protocol.WriteJSONLine(c.writer, data)
}

func (c *StreamAdminConn) RemoteAddr() string {
	return c.addr
}

func (c *StreamAdminConn) Close() error {
	if c.closer == nil {
		return nil
	}
	return c.closer.Close()
}

func remoteAddrString(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	return conn.RemoteAddr().String()
}
