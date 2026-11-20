// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package jsonrpc implements JSON-RPC client for plugin communication
package jsonrpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// ErrConnectionClosed indicates the plugin connection closed before a response arrived.
var ErrConnectionClosed = errors.New("plugin connection closed")

// ErrWriteStalled reports a frame whose write had begun but not finished when
// the call sending it ended: the plugin is not reading its input fast enough,
// or at all. Part of the frame may be in that input, so the client fails, and
// every later call returns this error.
var ErrWriteStalled = errors.New("plugin did not read its input")

// errWriterBusy is Shutdown's answer when another frame is still being written.
var errWriterBusy = errors.New("another frame is still being written")

// shutdownWriterWait is how long Shutdown waits for another frame's write to
// finish: long enough for a plugin that is reading, too short to hold up a
// stop behind one that is not.
const shutdownWriterWait = 100 * time.Millisecond

// Client handles JSON-RPC communication with a plugin
type Client struct {
	writer  io.Writer
	scanner *bufio.Scanner

	// Request tracking
	requestID uint64
	pending   map[uint64]chan *Response
	mu        sync.Mutex

	// writeSlot holds one token while a frame is being written. A channel
	// rather than a mutex, so waiting for it can end with the call.
	writeSlot chan struct{}
	// done closes when the client fails (terminalErr is set).
	done chan struct{}

	// Error handling
	lastError   error
	terminalErr error
}

// NewClient creates a new JSON-RPC client
func NewClient(reader io.Reader, writer io.Writer) *Client {
	scanner := bufio.NewScanner(reader)
	// Increase buffer size to handle large transaction payloads (up to 1MB)
	// Default is 64KB which may be insufficient for large transaction groups
	const maxScanTokenSize = 1024 * 1024 // 1MB
	buf := make([]byte, maxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)

	return &Client{
		writer:    writer,
		scanner:   scanner,
		pending:   make(map[uint64]chan *Response),
		writeSlot: make(chan struct{}, 1),
		done:      make(chan struct{}),
	}
}

// CallWithTimeout makes a JSON-RPC call with a custom timeout
func (c *Client) CallWithTimeout(method string, params interface{}, result interface{}, timeout time.Duration) error {
	return c.CallContext(context.Background(), method, params, result, timeout)
}

// CallContext makes a JSON-RPC call that also ends when ctx does, returning
// ctx's error wrapped. The peer is then still working on the request, and a
// late answer is dropped. timeout and ctx bound the whole call, sending the
// request included; a request cut off mid-write fails the client (see
// ErrWriteStalled).
func (c *Client) CallContext(ctx context.Context, method string, params interface{}, result interface{}, timeout time.Duration) error {
	return c.call(ctx, method, params, result, timeout, 0)
}

// Shutdown sends the shutdown request and waits up to timeout for the answer.
// It sends nothing if another frame is still being written after
// shutdownWriterWait: the plugin has not read that one, so it would not read
// this one in time either, and its input is about to be closed.
func (c *Client) Shutdown(timeout time.Duration) error {
	return c.call(context.Background(), MethodShutdown, ShutdownParams{}, nil, timeout, shutdownWriterWait)
}

// call makes one call. maxWriterWait, when positive, bounds the wait for
// another frame's write to finish; zero waits for as long as the call lasts.
func (c *Client) call(ctx context.Context, method string, params interface{}, result interface{}, timeout, maxWriterWait time.Duration) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("request not sent: %w", err)
	}
	// Generate request ID
	id := atomic.AddUint64(&c.requestID, 1)

	// Create request
	request := NewRequest(method, params, id)

	// Create response channel
	respChan := make(chan *Response, 1)

	// Register pending request
	c.mu.Lock()
	if c.terminalErr != nil {
		err := c.terminalErr
		c.mu.Unlock()
		return err
	}
	c.pending[id] = respChan
	c.mu.Unlock()

	// Clean up on exit
	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()

	callCtx, cancel := context.WithTimeoutCause(ctx, timeout, fmt.Errorf("request timeout after %v", timeout))
	defer cancel()

	// Send request
	if err := c.writeFrame(callCtx, request, maxWriterWait); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("request abandoned: %w", ctx.Err())
		}
		return fmt.Errorf("failed to send request: %w", err)
	}

	// Wait for response with timeout
	select {
	case resp, ok := <-respChan:
		if !ok {
			// The client failed; report its first failure, as later calls do.
			if err := c.terminalError(); err != nil {
				return err
			}
			return ErrConnectionClosed
		}
		if resp.Error != nil {
			return resp.Error
		}
		if result != nil {
			return resp.ParseResult(result)
		}
		return nil

	case <-callCtx.Done():
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("request abandoned: %w", err)
		}
		return context.Cause(callCtx)
	}
}

// Start begins reading responses from the plugin
func (c *Client) Start() {
	go c.readLoop()
}

// readLoop continuously reads responses from the plugin
func (c *Client) readLoop() {
	for c.scanner.Scan() {
		line := c.scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var frame rpcFrame
		if err := json.Unmarshal(line, &frame); err != nil {
			c.setLastError(fmt.Errorf("failed to unmarshal JSON-RPC frame: %w", err))
			continue
		}

		if frame.Method != "" {
			// Off the read goroutine: a reply the plugin does not read must
			// not stop its answers to apshell's calls being read.
			go c.handleInboundRequest(frame)
			continue
		}
		// A response carries a result member (possibly null) or an error.
		if len(frame.Result) == 0 && frame.Error == nil {
			c.setLastError(fmt.Errorf("invalid JSON-RPC frame without method, result, or error"))
			continue
		}
		response := Response{
			Jsonrpc: frame.Jsonrpc,
			Result:  frame.Result,
			Error:   frame.Error,
			ID:      frame.ID,
		}
		id, err := normalizeResponseID(response.ID)
		if err != nil {
			c.setLastError(fmt.Errorf("invalid response id: %w", err))
			continue
		}

		c.deliverResponse(id, &response)
	}

	if err := c.scanner.Err(); err != nil {
		c.failPending(fmt.Errorf("scanner error: %w", err))
		return
	}

	c.failPending(ErrConnectionClosed)
}

// rpcFrame is one inbound line. Result is a non-pointer RawMessage so that a
// "result": null member decodes to the bytes "null" rather than to nothing.
type rpcFrame struct {
	Jsonrpc string          `json:"jsonrpc"`
	Method  string          `json:"method,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
	ID      interface{}     `json:"id,omitempty"`
}

// handleInboundRequest answers a plugin-initiated request. apshell serves no
// plugin-to-host methods, so a well-formed request is answered
// method-not-found.
func (c *Client) handleInboundRequest(frame rpcFrame) {
	switch {
	case frame.Jsonrpc != Version:
		c.respondToInbound(frame.ID, &Error{Code: InvalidRequest, Message: "invalid JSON-RPC version"})
	case !validIDType(frame.ID):
		c.respondToInbound(frame.ID, &Error{Code: InvalidRequest, Message: fmt.Sprintf("invalid request id type %T", frame.ID)})
	default:
		c.respondToInbound(frame.ID, &Error{Code: MethodNotFound, Message: fmt.Sprintf("method not found: %s", frame.Method)})
	}
}

// respondToInbound sends rpcErr as the reply to request id. A notification,
// with no id, gets no reply.
func (c *Client) respondToInbound(id interface{}, rpcErr *Error) {
	if id == nil {
		return
	}
	// No call bounds a reply, so it waits for as long as the client lasts. A
	// plugin that stops reading also stops answering the call in progress, and
	// that call's end tears the plugin down.
	if err := c.writeFrame(context.Background(), &Response{Jsonrpc: Version, Error: rpcErr, ID: id}, 0); err != nil {
		c.setLastError(fmt.Errorf("failed to write callback response: %w", err))
	}
}

// writeFrame writes v as one line. It gives up when ctx ends or the client
// fails. A frame it gives up on while waiting for another to finish is not
// sent; one it gives up on mid-write fails the client with ErrWriteStalled,
// since the plugin's input may now hold part of it. The abandoned Write
// itself returns once the writer is closed, as the manager does when it stops
// the plugin. A positive maxWriterWait bounds the wait for another frame's
// write; a frame still waiting after it is not sent. A frame whose ctx has
// already ended is not sent either.
func (c *Client) writeFrame(ctx context.Context, v interface{}, maxWriterWait time.Duration) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON-RPC frame: %w", err)
	}
	data = append(data, '\n')

	var writerBusy <-chan time.Time // nil, so never ready, unless bounded
	if maxWriterWait > 0 {
		timer := time.NewTimer(maxWriterWait)
		defer timer.Stop()
		writerBusy = timer.C
	}
	select {
	case c.writeSlot <- struct{}{}:
	case <-c.done:
		return c.terminalError()
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-writerBusy:
		return errWriterBusy
	}
	// The writer and an ending ctx can be ready together, and select picks
	// either: send nothing once ctx has ended.
	if ctx.Err() != nil {
		<-c.writeSlot
		return context.Cause(ctx)
	}

	written := make(chan error, 1)
	go func() {
		err := c.writeHeld(data)
		// Free the writer before reporting, so a frame sent right after
		// this one returns never finds it held.
		<-c.writeSlot
		written <- err
	}()
	select {
	case err := <-written:
		return err
	case <-c.done:
		return c.terminalError()
	case <-ctx.Done():
		// A write that finished as ctx ended went out whole.
		select {
		case err := <-written:
			return err
		default:
		}
		return c.failWrite(ctx)
	}
}

// writeHeld writes data; the caller holds writeSlot. A failed client writes
// nothing more: a frame abandoned before it may have been cut short.
func (c *Client) writeHeld(data []byte) error {
	if err := c.terminalError(); err != nil {
		return err
	}
	n, err := c.writer.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write JSON-RPC frame: %w", err)
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

// failWrite fails the client for a frame cut off mid-write when ctx ended.
func (c *Client) failWrite(ctx context.Context) error {
	err := fmt.Errorf("%w: %w", ErrWriteStalled, context.Cause(ctx))
	c.failPending(err)
	return err
}

func normalizeResponseID(id interface{}) (uint64, error) {
	switch v := id.(type) {
	case float64:
		if v < 0 || math.Trunc(v) != v || v > math.MaxUint64 {
			return 0, fmt.Errorf("non-integral numeric id %v", v)
		}
		return uint64(v), nil
	default:
		return 0, fmt.Errorf("unsupported id type %T", id)
	}
}

func (c *Client) setLastError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastError = err
}

func (c *Client) deliverResponse(id uint64, response *Response) {
	c.mu.Lock()
	defer c.mu.Unlock()

	respChan, ok := c.pending[id]
	if !ok {
		return
	}
	delete(c.pending, id)
	respChan <- response
}

// failPending fails the client. The first failure is the one later calls
// report.
func (c *Client) failPending(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.lastError = err
	if c.terminalErr == nil {
		c.terminalErr = err
		close(c.done)
	}
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
}

func (c *Client) terminalError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.terminalErr
}

// GetLastError returns the last error encountered during reading
func (c *Client) GetLastError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastError
}

// Close closes the client (doesn't close underlying reader/writer)
func (c *Client) Close() {
	c.failPending(ErrConnectionClosed)
}
