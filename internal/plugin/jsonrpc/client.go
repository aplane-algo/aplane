// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package jsonrpc implements JSON-RPC client for plugin communication
package jsonrpc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Client handles JSON-RPC communication with a plugin
type Client struct {
	reader  io.Reader
	writer  io.Writer
	scanner *bufio.Scanner

	// Request tracking
	requestID uint64
	pending   map[interface{}]chan *Response
	mu        sync.Mutex

	// Error handling
	lastError error
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
		reader:  reader,
		writer:  writer,
		scanner: scanner,
		pending: make(map[interface{}]chan *Response),
	}
}

// Call makes a JSON-RPC call and waits for the response
func (c *Client) Call(method string, params interface{}, result interface{}) error {
	return c.CallWithTimeout(method, params, result, 30*time.Second)
}

// CallWithTimeout makes a JSON-RPC call with a custom timeout
func (c *Client) CallWithTimeout(method string, params interface{}, result interface{}, timeout time.Duration) error {
	// Generate request ID
	id := atomic.AddUint64(&c.requestID, 1)

	// Create request
	request := NewRequest(method, params, id)

	// Create response channel
	respChan := make(chan *Response, 1)

	// Register pending request
	c.mu.Lock()
	c.pending[id] = respChan
	c.mu.Unlock()

	// Clean up on exit
	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()

	// Send request
	if err := c.sendRequest(request); err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	// Wait for response with timeout
	select {
	case resp := <-respChan:
		if resp.HasError() {
			return fmt.Errorf("RPC error %d: %s", resp.Error.Code, resp.Error.Message)
		}
		if result != nil && resp.Result != nil {
			return resp.ParseResult(result)
		}
		return nil

	case <-time.After(timeout):
		return fmt.Errorf("request timeout after %v", timeout)
	}
}

// Notify sends a notification (no response expected)
func (c *Client) Notify(method string, params interface{}) error {
	request := NewRequest(method, params, nil)
	return c.sendRequest(request)
}

// sendRequest sends a request to the plugin
func (c *Client) sendRequest(request *Request) error {
	data, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Write JSON followed by newline
	if _, err := c.writer.Write(data); err != nil {
		return fmt.Errorf("failed to write request: %w", err)
	}

	if _, err := c.writer.Write([]byte("\n")); err != nil {
		return fmt.Errorf("failed to write newline: %w", err)
	}

	return nil
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

		var response Response
		if err := json.Unmarshal(line, &response); err != nil {
			c.lastError = fmt.Errorf("failed to unmarshal response: %w", err)
			continue
		}

		// Normalize response ID to uint64 for lookup
		// JSON unmarshaler converts numeric IDs to float64
		var id uint64
		switch v := response.ID.(type) {
		case float64:
			id = uint64(v)
		case uint64:
			id = v
		default:
			// Skip responses with non-numeric IDs
			continue
		}

		// Find pending request
		c.mu.Lock()
		respChan, ok := c.pending[id]
		c.mu.Unlock()

		if ok {
			// Send response to waiting caller
			select {
			case respChan <- &response:
			default:
				// Channel full or closed
			}
		}
	}

	if err := c.scanner.Err(); err != nil {
		c.lastError = fmt.Errorf("scanner error: %w", err)
	}
}

// GetLastError returns the last error encountered during reading
func (c *Client) GetLastError() error {
	return c.lastError
}

// Close closes the client (doesn't close underlying reader/writer)
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Close all pending response channels
	for _, ch := range c.pending {
		close(ch)
	}
	c.pending = make(map[interface{}]chan *Response)
}
