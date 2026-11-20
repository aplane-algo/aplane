// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package jsonrpc implements the JSON-RPC protocol for plugin communication
package jsonrpc

import (
	"bytes"
	"encoding/json"
	"fmt"
)

const Version = "2.0"

// Request represents a JSON-RPC request from apshell to plugin
type Request struct {
	Jsonrpc string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
	ID      interface{} `json:"id"`
}

// Response represents a JSON-RPC response from plugin to apshell. Result
// holds the raw "result" member, so a JSON null result is the four bytes
// "null" and an absent member is empty.
type Response struct {
	Jsonrpc string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
	ID      interface{}     `json:"id"`
}

// Error represents a JSON-RPC error
type Error struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("RPC error %d: %s", e.Code, e.Message)
}

// Standard JSON-RPC error codes
const (
	InvalidRequest = -32600
	MethodNotFound = -32601
)

// NewRequest creates a new JSON-RPC request
func NewRequest(method string, params interface{}, id interface{}) *Request {
	return &Request{
		Jsonrpc: Version,
		Method:  method,
		Params:  params,
		ID:      id,
	}
}

// ParseResult unmarshals the result into the provided interface. A null
// result is refused: the caller asked for a value, and decoding null would
// leave v at its zero value with no error.
func (r *Response) ParseResult(v interface{}) error {
	if len(r.Result) == 0 {
		return fmt.Errorf("no result in response")
	}
	if bytes.Equal(bytes.TrimSpace(r.Result), []byte("null")) {
		return fmt.Errorf("null result in response")
	}

	if err := json.Unmarshal(r.Result, v); err != nil {
		return fmt.Errorf("failed to unmarshal result: %w", err)
	}

	return nil
}

func validIDType(id interface{}) bool {
	if id == nil {
		return true
	}
	switch id.(type) {
	case float64, string:
		return true
	default:
		return false
	}
}
