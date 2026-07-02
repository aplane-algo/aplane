// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsonrpc

import (
	"encoding/json"
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
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
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
		{
			name:   "parse raw message params",
			params: json.RawMessage(`{"name":"raw","value":7}`),
			want:   testParams{Name: "raw", Value: 7},
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

func TestCallbackPayloadJSONShapes(t *testing.T) {
	tests := []struct {
		name string
		in   interface{}
		want string
	}{
		{
			name: "list accounts result",
			in:   ListAccountsResult{Accounts: []string{"ADDR1", "ADDR2"}},
			want: `{"accounts":["ADDR1","ADDR2"]}`,
		},
		{
			name: "get asset info params",
			in:   GetAssetInfoParams{AssetID: 10458941},
			want: `{"assetId":10458941}`,
		},
		{
			name: "get asset info result",
			in:   GetAssetInfoResult{AssetID: 10458941, Name: "USD Coin", UnitName: "USDC", Decimals: 6},
			want: `{"assetId":10458941,"name":"USD Coin","unitName":"USDC","decimals":6}`,
		},
		{
			name: "get app info params",
			in:   GetAppInfoParams{AppID: 1234},
			want: `{"appId":1234}`,
		},
		{
			name: "get app info result",
			in:   GetAppInfoResult{AppID: 1234, Creator: "ADDR"},
			want: `{"appId":1234,"creator":"ADDR"}`,
		},
		{
			name: "sign transaction params",
			in:   SignTransactionParams{Encoded: "TXN", Description: "Sign one transaction"},
			want: `{"encoded":"TXN","description":"Sign one transaction"}`,
		},
		{
			name: "sign transaction result",
			in:   SignTransactionResult{Signed: "SIGNED"},
			want: `{"signed":"SIGNED"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.in)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("Marshal() = %s, want %s", got, tt.want)
			}
		})
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
	resultData := json.RawMessage(`{"success":true}`)
	original := Response{
		Jsonrpc: Version,
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
	if decoded.Error != nil {
		t.Error("unexpected error in decoded response")
	}

	// Test error response
	errorResp := Response{
		Jsonrpc: Version,
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

	if decodedErr.Error == nil {
		t.Error("expected error in decoded response")
	}
	if decodedErr.Error.Code != InvalidParams {
		t.Errorf("Error.Code = %d, want %d", decodedErr.Error.Code, InvalidParams)
	}
}
