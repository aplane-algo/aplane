// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

type displacementTestRead struct {
	line []byte
	err  error
}

type displacementTestConn struct {
	mu        sync.Mutex
	reads     chan displacementTestRead
	writes    [][]byte
	writeErr  error
	closed    chan struct{}
	closeOnce sync.Once
}

func newDisplacementTestConn() *displacementTestConn {
	return &displacementTestConn{
		reads:  make(chan displacementTestRead, 1),
		closed: make(chan struct{}),
	}
}

func (c *displacementTestConn) ReadMessage() ([]byte, error) {
	select {
	case read := <-c.reads:
		return read.line, read.err
	case <-c.closed:
		return nil, errors.New("connection closed")
	}
}

func (c *displacementTestConn) WriteMessage(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeErr != nil {
		return c.writeErr
	}
	c.writes = append(c.writes, data)
	return nil
}

func (c *displacementTestConn) RemoteAddr() string {
	return "test-client"
}

func (c *displacementTestConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return nil
}

func (c *displacementTestConn) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.writes)
}

func TestOfferDisplacementTimeoutClosesNewConnection(t *testing.T) {
	conn := newDisplacementTestConn()

	if OfferDisplacement(conn, 10*time.Millisecond) {
		t.Fatal("OfferDisplacement() = true, want false")
	}
	if got := conn.writeCount(); got != 1 {
		t.Fatalf("WriteMessage() calls = %d, want 1", got)
	}

	select {
	case <-conn.closed:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for rejected displacement connection to close")
	}
}

func TestOfferDisplacementConfirmKeepsConnectionOpen(t *testing.T) {
	conn := newDisplacementTestConn()
	confirm, err := protocol.MarshalAdminMessage(protocol.DisplaceConfirmMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeDisplaceConfirm},
	})
	if err != nil {
		t.Fatalf("MarshalAdminMessage() error = %v", err)
	}
	conn.reads <- displacementTestRead{line: confirm}

	if !OfferDisplacement(conn, time.Second) {
		t.Fatal("OfferDisplacement() = false, want true")
	}

	select {
	case <-conn.closed:
		t.Fatal("connection closed after confirmed displacement")
	default:
	}
}
