// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package jsonrpc implements the JSON-RPC protocol for plugin communication
package jsonrpc

import (
	"encoding/json"
	"fmt"
)

// Request represents a JSON-RPC request from apshell to plugin
type Request struct {
	Jsonrpc string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
	ID      interface{} `json:"id"`
}

// Response represents a JSON-RPC response from plugin to apshell
type Response struct {
	Jsonrpc string           `json:"jsonrpc"`
	Result  *json.RawMessage `json:"result,omitempty"`
	Error   *Error           `json:"error,omitempty"`
	ID      interface{}      `json:"id"`
}

// Error represents a JSON-RPC error
type Error struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Standard JSON-RPC error codes
const (
	ParseError     = -32700
	InvalidRequest = -32600
	MethodNotFound = -32601
	InvalidParams  = -32602
	InternalError  = -32603
)

// Custom error codes for apshell plugins
const (
	// Plugin-specific errors start at -32000
	PluginError         = -32000
	NetworkError        = -32001
	AuthenticationError = -32002
	InsufficientFunds   = -32003
	InvalidAddress      = -32004
	TransactionFailed   = -32005
)

// NewRequest creates a new JSON-RPC request
func NewRequest(method string, params interface{}, id interface{}) *Request {
	return &Request{
		Jsonrpc: "2.0",
		Method:  method,
		Params:  params,
		ID:      id,
	}
}

// Validate checks if a request is valid
func (r *Request) Validate() error {
	if r.Jsonrpc != "2.0" {
		return fmt.Errorf("invalid JSON-RPC version: %s", r.Jsonrpc)
	}

	if r.Method == "" {
		return fmt.Errorf("method is required")
	}

	// ID can be null, number, or string
	if r.ID != nil {
		switch r.ID.(type) {
		case float64, string:
			// Valid
		default:
			return fmt.Errorf("invalid ID type: %T", r.ID)
		}
	}

	return nil
}

// IsNotification checks if this is a notification (no response expected)
func (r *Request) IsNotification() bool {
	return r.ID == nil
}

// ParseParams unmarshals params into the provided interface
func (r *Request) ParseParams(v interface{}) error {
	if r.Params == nil {
		return nil
	}

	bytes, err := json.Marshal(r.Params)
	if err != nil {
		return fmt.Errorf("failed to marshal params: %w", err)
	}

	if err := json.Unmarshal(bytes, v); err != nil {
		return fmt.Errorf("failed to unmarshal params: %w", err)
	}

	return nil
}

// ParseResult unmarshals the result into the provided interface
func (r *Response) ParseResult(v interface{}) error {
	if r.Result == nil {
		return fmt.Errorf("no result in response")
	}

	if err := json.Unmarshal(*r.Result, v); err != nil {
		return fmt.Errorf("failed to unmarshal result: %w", err)
	}

	return nil
}

// HasError checks if the response contains an error
func (r *Response) HasError() bool {
	return r.Error != nil
}

// GetError returns the error message if present
func (r *Response) GetError() string {
	if r.Error == nil {
		return ""
	}
	return r.Error.Message
}
