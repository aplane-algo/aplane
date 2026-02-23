// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package jsonrpc

import (
	"encoding/json"
	"testing"
)

func TestNewRequest(t *testing.T) {
	tests := []struct {
		name   string
		method string
		params interface{}
		id     interface{}
	}{
		{
			name:   "basic request",
			method: "execute",
			params: map[string]string{"key": "value"},
			id:     1.0,
		},
		{
			name:   "string id",
			method: "initialize",
			params: nil,
			id:     "req-123",
		},
		{
			name:   "notification (nil id)",
			method: "shutdown",
			params: nil,
			id:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := NewRequest(tt.method, tt.params, tt.id)

			if req.Jsonrpc != "2.0" {
				t.Errorf("Jsonrpc = %q, want %q", req.Jsonrpc, "2.0")
			}
			if req.Method != tt.method {
				t.Errorf("Method = %q, want %q", req.Method, tt.method)
			}
			if req.ID != tt.id {
				t.Errorf("ID = %v, want %v", req.ID, tt.id)
			}
		})
	}
}

func TestRequestValidate(t *testing.T) {
	tests := []struct {
		name    string
		request Request
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid request with numeric id",
			request: Request{
				Jsonrpc: "2.0",
				Method:  "execute",
				ID:      1.0,
			},
			wantErr: false,
		},
		{
			name: "valid request with string id",
			request: Request{
				Jsonrpc: "2.0",
				Method:  "execute",
				ID:      "req-123",
			},
			wantErr: false,
		},
		{
			name: "valid notification (nil id)",
			request: Request{
				Jsonrpc: "2.0",
				Method:  "shutdown",
				ID:      nil,
			},
			wantErr: false,
		},
		{
			name: "invalid jsonrpc version",
			request: Request{
				Jsonrpc: "1.0",
				Method:  "execute",
				ID:      1.0,
			},
			wantErr: true,
			errMsg:  "invalid JSON-RPC version",
		},
		{
			name: "empty jsonrpc version",
			request: Request{
				Jsonrpc: "",
				Method:  "execute",
				ID:      1.0,
			},
			wantErr: true,
			errMsg:  "invalid JSON-RPC version",
		},
		{
			name: "empty method",
			request: Request{
				Jsonrpc: "2.0",
				Method:  "",
				ID:      1.0,
			},
			wantErr: true,
			errMsg:  "method is required",
		},
		{
			name: "invalid id type (int)",
			request: Request{
				Jsonrpc: "2.0",
				Method:  "execute",
				ID:      123, // int, not float64
			},
			wantErr: true,
			errMsg:  "invalid ID type",
		},
		{
			name: "invalid id type (bool)",
			request: Request{
				Jsonrpc: "2.0",
				Method:  "execute",
				ID:      true,
			},
			wantErr: true,
			errMsg:  "invalid ID type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want containing %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestRequestIsNotification(t *testing.T) {
	tests := []struct {
		name string
		id   interface{}
		want bool
	}{
		{"nil id is notification", nil, true},
		{"numeric id is not notification", 1.0, false},
		{"string id is not notification", "req-1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &Request{ID: tt.id}
			if got := req.IsNotification(); got != tt.want {
				t.Errorf("IsNotification() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRequestParseParams(t *testing.T) {
	type testParams struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	tests := []struct {
		name    string
		params  interface{}
		want    testParams
		wantErr bool
	}{
		{
			name:   "parse map params",
			params: map[string]interface{}{"name": "test", "value": 42.0},
			want:   testParams{Name: "test", Value: 42},
		},
		{
			name:   "nil params",
			params: nil,
			want:   testParams{},
		},
		{
			name:   "empty params",
			params: map[string]interface{}{},
			want:   testParams{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &Request{Params: tt.params}
			var got testParams
			err := req.ParseParams(&got)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("ParseParams() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestResponseParseResult(t *testing.T) {
	type testResult struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}

	tests := []struct {
		name    string
		result  string // JSON string
		want    testResult
		wantErr bool
		errMsg  string
	}{
		{
			name:   "parse valid result",
			result: `{"success":true,"message":"ok"}`,
			want:   testResult{Success: true, Message: "ok"},
		},
		{
			name:    "nil result",
			result:  "",
			wantErr: true,
			errMsg:  "no result in response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp Response
			if tt.result != "" {
				raw := json.RawMessage(tt.result)
				resp.Result = &raw
			}

			var got testResult
			err := resp.ParseResult(&got)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want containing %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("ParseResult() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestResponseHasError(t *testing.T) {
	tests := []struct {
		name string
		err  *Error
		want bool
	}{
		{"nil error", nil, false},
		{"has error", &Error{Code: -32600, Message: "Invalid Request"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &Response{Error: tt.err}
			if got := resp.HasError(); got != tt.want {
				t.Errorf("HasError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResponseGetError(t *testing.T) {
	tests := []struct {
		name string
		err  *Error
		want string
	}{
		{"nil error", nil, ""},
		{"has error", &Error{Code: -32600, Message: "Invalid Request"}, "Invalid Request"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &Response{Error: tt.err}
			if got := resp.GetError(); got != tt.want {
				t.Errorf("GetError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrorCodes(t *testing.T) {
	// Verify standard JSON-RPC error codes
	tests := []struct {
		name string
		code int
		want int
	}{
		{"ParseError", ParseError, -32700},
		{"InvalidRequest", InvalidRequest, -32600},
		{"MethodNotFound", MethodNotFound, -32601},
		{"InvalidParams", InvalidParams, -32602},
		{"InternalError", InternalError, -32603},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.code != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.code, tt.want)
			}
		})
	}

	// Verify custom error codes are in valid range (-32000 to -32099)
	customCodes := []struct {
		name string
		code int
	}{
		{"PluginError", PluginError},
		{"NetworkError", NetworkError},
		{"AuthenticationError", AuthenticationError},
		{"InsufficientFunds", InsufficientFunds},
		{"InvalidAddress", InvalidAddress},
		{"TransactionFailed", TransactionFailed},
	}

	for _, tt := range customCodes {
		t.Run(tt.name+" in range", func(t *testing.T) {
			if tt.code > -32000 || tt.code < -32099 {
				t.Errorf("%s = %d, want in range [-32099, -32000]", tt.name, tt.code)
			}
		})
	}
}

func TestJSONRoundTrip(t *testing.T) {
	// Test that requests can be marshaled and unmarshaled correctly
	original := NewRequest("execute", map[string]interface{}{
		"command": "test",
		"args":    []string{"arg1", "arg2"},
	}, 1.0)

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded Request
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Jsonrpc != original.Jsonrpc {
		t.Errorf("Jsonrpc = %q, want %q", decoded.Jsonrpc, original.Jsonrpc)
	}
	if decoded.Method != original.Method {
		t.Errorf("Method = %q, want %q", decoded.Method, original.Method)
	}
	// ID comparison (JSON unmarshals numbers as float64)
	if decoded.ID != original.ID {
		t.Errorf("ID = %v, want %v", decoded.ID, original.ID)
	}
}

func TestResponseJSONRoundTrip(t *testing.T) {
	// Test successful response
	resultData := json.RawMessage(`{"success":true}`)
	original := Response{
		Jsonrpc: "2.0",
		Result:  &resultData,
		ID:      1.0,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded Response
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Jsonrpc != original.Jsonrpc {
		t.Errorf("Jsonrpc = %q, want %q", decoded.Jsonrpc, original.Jsonrpc)
	}
	if decoded.HasError() {
		t.Error("unexpected error in decoded response")
	}

	// Test error response
	errorResp := Response{
		Jsonrpc: "2.0",
		Error:   &Error{Code: InvalidParams, Message: "missing required field"},
		ID:      2.0,
	}

	data, err = json.Marshal(errorResp)
	if err != nil {
		t.Fatalf("failed to marshal error response: %v", err)
	}

	var decodedErr Response
	if err := json.Unmarshal(data, &decodedErr); err != nil {
		t.Fatalf("failed to unmarshal error response: %v", err)
	}

	if !decodedErr.HasError() {
		t.Error("expected error in decoded response")
	}
	if decodedErr.Error.Code != InvalidParams {
		t.Errorf("Error.Code = %d, want %d", decodedErr.Error.Code, InvalidParams)
	}
}

// contains checks if s contains substr
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
