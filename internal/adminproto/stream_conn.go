// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminproto

import (
	"bufio"
	"io"
	"net"
	"sync"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// StreamAdminConn adapts a line-delimited stream to a transport-neutral admin
// protocol connection.
type StreamAdminConn struct {
	closer  io.Closer
	reader  *bufio.Reader
	addr    string
	writeMu *sync.Mutex
	writer  io.Writer
}

func NewStreamAdminConn(rw io.ReadWriteCloser, addr string, writeMu *sync.Mutex) *StreamAdminConn {
	return &StreamAdminConn{
		closer:  rw,
		reader:  bufio.NewReader(rw),
		addr:    addr,
		writeMu: writeMu,
		writer:  rw,
	}
}

func NewUnixAdminConn(conn net.Conn, reader *bufio.Reader, writeMu *sync.Mutex) *StreamAdminConn {
	if reader == nil && conn != nil {
		reader = bufio.NewReader(conn)
	}
	return &StreamAdminConn{
		closer:  conn,
		reader:  reader,
		addr:    remoteAddrString(conn),
		writeMu: writeMu,
		writer:  conn,
	}
}

func (c *StreamAdminConn) ReadMessage() ([]byte, error) {
	return protocol.ReadJSONLine(c.reader)
}

func (c *StreamAdminConn) WriteMessage(data []byte) error {
	if c.writeMu != nil {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
	}
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
