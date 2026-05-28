// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package jsonrpc implements JSON-RPC client for plugin communication
package jsonrpc

import (
	"bufio"
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

// Client handles JSON-RPC communication with a plugin
type Client struct {
	reader  io.Reader
	writer  io.Writer
	scanner *bufio.Scanner

	// Request tracking
	requestID uint64
	pending   map[uint64]chan *Response
	mu        sync.Mutex
	writeMu   sync.Mutex

	requestHandler RequestHandler

	// Error handling
	lastError   error
	terminalErr error
}

// RequestHandler handles plugin-initiated JSON-RPC requests back into apshell.
type RequestHandler interface {
	HandleRequest(method string, params json.RawMessage) (interface{}, *Error)
}

// RequestHandlerFunc adapts a function into a RequestHandler.
type RequestHandlerFunc func(method string, params json.RawMessage) (interface{}, *Error)

func (fn RequestHandlerFunc) HandleRequest(method string, params json.RawMessage) (interface{}, *Error) {
	return fn(method, params)
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
		pending: make(map[uint64]chan *Response),
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

	// Send request
	if err := c.sendRequest(request); err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	// Wait for response with timeout
	select {
	case resp, ok := <-respChan:
		if !ok {
			if err := c.GetLastError(); err != nil {
				return err
			}
			return ErrConnectionClosed
		}
		if resp.Error != nil {
			return resp.Error
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

// SetRequestHandler installs the handler used for plugin-initiated requests.
func (c *Client) SetRequestHandler(handler RequestHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requestHandler = handler
}

// sendRequest sends a request to the plugin
func (c *Client) sendRequest(request *Request) error {
	return c.writeJSONLine(request)
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
			go c.handleInboundRequest(frame)
			continue
		}
		if frame.Result == nil && frame.Error == nil {
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

type rpcFrame struct {
	Jsonrpc string           `json:"jsonrpc"`
	Method  string           `json:"method,omitempty"`
	Params  json.RawMessage  `json:"params,omitempty"`
	Result  *json.RawMessage `json:"result,omitempty"`
	Error   *Error           `json:"error,omitempty"`
	ID      interface{}      `json:"id,omitempty"`
}

func (c *Client) handleInboundRequest(frame rpcFrame) {
	if frame.Jsonrpc != Version {
		c.respondToInbound(frame.ID, nil, &Error{Code: InvalidRequest, Message: "invalid JSON-RPC version"})
		return
	}
	if !validIDType(frame.ID) {
		c.respondToInbound(frame.ID, nil, &Error{Code: InvalidRequest, Message: fmt.Sprintf("invalid request id type %T", frame.ID)})
		return
	}

	handler := c.getRequestHandler()
	if handler == nil {
		c.respondToInbound(frame.ID, nil, &Error{Code: MethodNotFound, Message: fmt.Sprintf("method not found: %s", frame.Method)})
		return
	}
	result, rpcErr := handler.HandleRequest(frame.Method, frame.Params)
	c.respondToInbound(frame.ID, result, rpcErr)
}

func (c *Client) getRequestHandler() RequestHandler {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requestHandler
}

func (c *Client) respondToInbound(id interface{}, result interface{}, rpcErr *Error) {
	if id == nil {
		return
	}
	response := Response{
		Jsonrpc: Version,
		Error:   rpcErr,
		ID:      id,
	}
	if rpcErr == nil {
		raw, err := json.Marshal(result)
		if err != nil {
			response.Error = &Error{Code: InternalError, Message: fmt.Sprintf("failed to marshal callback result: %v", err)}
		} else {
			resultJSON := json.RawMessage(raw)
			response.Result = &resultJSON
		}
	}
	if err := c.writeJSONLine(&response); err != nil {
		c.setLastError(fmt.Errorf("failed to write callback response: %w", err))
	}
}

func (c *Client) writeJSONLine(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON-RPC frame: %w", err)
	}
	data = append(data, '\n')

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	n, err := c.writer.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write JSON-RPC frame: %w", err)
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func normalizeResponseID(id interface{}) (uint64, error) {
	switch v := id.(type) {
	case float64:
		if v < 0 || math.Trunc(v) != v || v > math.MaxUint64 {
			return 0, fmt.Errorf("non-integral numeric id %v", v)
		}
		return uint64(v), nil
	case uint64:
		return v, nil
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

func (c *Client) failPending(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.lastError = err
	c.terminalErr = err
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
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
