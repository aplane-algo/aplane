// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsonrpc

import (
	"encoding/json"
	"reflect"
	"strings"
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

			if req.Jsonrpc != Version {
				t.Errorf("Jsonrpc = %q, want %q", req.Jsonrpc, Version)
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

func TestPluginProtocolIdentifier(t *testing.T) {
	if PluginProtocol != "aplane-plugin/2" {
		t.Fatalf("PluginProtocol = %q, want aplane-plugin/2", PluginProtocol)
	}
	if PluginProtocol == Version {
		t.Fatalf("plugin protocol %q must differ from JSON-RPC envelope version", PluginProtocol)
	}
}

func TestPluginSignerDecodesItsDeclaration(t *testing.T) {
	var signers []PluginSigner
	err := json.Unmarshal([]byte(`[
		{"address":"A","kind":"plugin-callback","signerRef":"r","lsigResources":{"programBytes":1,"argumentBytes":2,"maxOpcodeCost":3}},
		{"address":"B","kind":"plugin-callback","signerRef":"s","pqScheme":"f1","unknown":true}
	]`), &signers)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	want := []PluginSigner{
		{Address: "A", Kind: PluginSignerKindCallback, SignerRef: "r", LsigResources: &PluginLogicSigResources{ProgramBytes: 1, ArgumentBytes: 2, MaxOpcodeCost: 3}},
		{Address: "B", Kind: PluginSignerKindCallback, SignerRef: "s", PQScheme: "f1"},
	}
	if !reflect.DeepEqual(signers, want) {
		t.Fatalf("decoded = %+v, want %+v", signers, want)
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
		{
			name:    "null result",
			result:  "null",
			wantErr: true,
			errMsg:  "null result in response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp Response
			if tt.result != "" {
				resp.Result = json.RawMessage(tt.result)
			}

			var got testResult
			err := resp.ParseResult(&got)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
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

func TestErrorImplementsError(t *testing.T) {
	err := (&Error{Code: InvalidRequest, Message: "Invalid Request"}).Error()
	if err != "RPC error -32600: Invalid Request" {
		t.Fatalf("Error() = %q, want %q", err, "RPC error -32600: Invalid Request")
	}
}

func TestErrorCodes(t *testing.T) {
	// Verify standard JSON-RPC error codes
	tests := []struct {
		name string
		code int
		want int
	}{
		{"InvalidRequest", InvalidRequest, -32600},
		{"MethodNotFound", MethodNotFound, -32601},
		{"InternalError", InternalError, -32603},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.code != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.code, tt.want)
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

func TestPluginExecutionContextOmitsReservedZeroFields(t *testing.T) {
	data, err := json.Marshal(Context{
		Accounts: []string{"ADDR1"},
		Network:  "testnet",
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	got := string(data)
	for _, unwanted := range []string{"round", "genesisId", "genesisHash"} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("Context JSON = %s, should omit %s", got, unwanted)
		}
	}
}

func TestExecuteResultUnsupportedLocalSignersJSONShape(t *testing.T) {
	result := ExecuteResult{
		Success:      true,
		LocalSigners: []json.RawMessage{json.RawMessage(`{"address":"ADDR1","secretKey":"SECRET"}`)},
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	want := `{"success":true,"localSigners":[{"address":"ADDR1","secretKey":"SECRET"}]}`
	if string(data) != want {
		t.Fatalf("Marshal() = %s, want %s", data, want)
	}
}

func TestResponseJSONRoundTrip(t *testing.T) {
	// Test successful response
	original := Response{
		Jsonrpc: Version,
		Result:  json.RawMessage(`{"success":true}`),
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
	if decoded.Error != nil {
		t.Error("unexpected error in decoded response")
	}

	// Test error response
	errorResp := Response{
		Jsonrpc: Version,
		Error:   &Error{Code: MethodNotFound, Message: "method not found"},
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

	if decodedErr.Error == nil {
		t.Error("expected error in decoded response")
	}
	if decodedErr.Error.Code != MethodNotFound {
		t.Errorf("Error.Code = %d, want %d", decodedErr.Error.Code, MethodNotFound)
	}
}
