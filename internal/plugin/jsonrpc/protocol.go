// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package jsonrpc implements the JSON-RPC protocol for plugin communication
package jsonrpc

import (
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

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("RPC error %d: %s", e.Code, e.Message)
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
		Jsonrpc: Version,
		Method:  method,
		Params:  params,
		ID:      id,
	}
}

// Validate checks if a request is valid
func (r *Request) Validate() error {
	if r.Jsonrpc != Version {
		return fmt.Errorf("invalid JSON-RPC version: %s", r.Jsonrpc)
	}

	if r.Method == "" {
		return fmt.Errorf("method is required")
	}

	if !validIDType(r.ID) {
		return fmt.Errorf("invalid ID type: %T", r.ID)
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
	return decodeJSONValue(r.Params, v, "params")
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

func decodeJSONValue(src interface{}, dst interface{}, field string) error {
	switch v := src.(type) {
	case json.RawMessage:
		if err := json.Unmarshal(v, dst); err != nil {
			return fmt.Errorf("failed to unmarshal %s: %w", field, err)
		}
		return nil
	case []byte:
		if err := json.Unmarshal(v, dst); err != nil {
			return fmt.Errorf("failed to unmarshal %s: %w", field, err)
		}
		return nil
	default:
		data, err := json.Marshal(src)
		if err != nil {
			return fmt.Errorf("failed to marshal %s: %w", field, err)
		}
		if err := json.Unmarshal(data, dst); err != nil {
			return fmt.Errorf("failed to unmarshal %s: %w", field, err)
		}
		return nil
	}
}
