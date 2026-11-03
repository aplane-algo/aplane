// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package transport

import (
	"io"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// StreamClient wraps an already-open admin stream and exposes dispatcher-backed
// notifications/lifecycle without owning reconnect or authentication policy.
type StreamClient struct {
	stream     io.ReadWriteCloser
	reader     *protocol.FrameReader
	dispatcher *dispatcher
	writeMu    sync.Mutex
}

// NewStreamClient creates a non-strict dispatcher over an existing admin stream.
// Unmatched inbound messages are surfaced as notifications so higher-level
// clients like the TUI can handle auth/status/result traffic directly.
func NewStreamClient(stream io.ReadWriteCloser) *StreamClient {
	client := &StreamClient{
		stream: stream,
		reader: protocol.NewFrameReader(stream),
	}
	client.dispatcher = newDispatcherWithMode(client, false)
	return client
}

func (c *StreamClient) Close() error {
	if c.stream == nil {
		return nil
	}
	// Close the underlying stream first so the dispatcher's read loop
	// receives an error and exits. Do not nil the reader or dispatcher
	// here — the read loop goroutine may still be referencing them.
	err := c.stream.Close()
	// Nothing reads notifications after Close; clear the queued raw frames.
	c.dispatcher.release()
	return err
}

func (c *StreamClient) WriteJSON(v interface{}) error {
	data, err := protocol.MarshalAdminMessage(v)
	if err != nil {
		return err
	}
	defer protocol.SensitiveBytes(data).Zero()
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return protocol.WriteJSONLine(c.stream, data)
}

func (c *StreamClient) ReadMessage() ([]byte, error) {
	return c.reader.ReadFrame()
}

// SendAndReceive sends a message and waits for the correlated response.
func (c *StreamClient) SendAndReceive(msg interface{}, timeout time.Duration) ([]byte, error) {
	return c.dispatcher.request(msg, timeout)
}

func (c *StreamClient) SetReadDeadline(_ time.Duration) {}

func (c *StreamClient) ClearReadDeadline() {}

func (c *StreamClient) Notifications() <-chan Notification {
	return c.dispatcher.notificationsChan()
}

func (c *StreamClient) LifecycleEvents() <-chan LifecycleEvent {
	return c.dispatcher.lifecycleChan()
}

var _ adminProtocolConn = (*StreamClient)(nil)
