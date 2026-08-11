// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerapi

import (
	"strings"
	"testing"
)

func TestSignRequestMode(t *testing.T) {
	tests := []struct {
		name    string
		request SignRequest
		want    RequestMode
		wantErr string
	}{
		{name: "sign mode", request: SignRequest{AuthAddress: "ADDR", TxnBytesHex: "deadbeef"}, want: RequestModeSign},
		{name: "foreign mode", request: SignRequest{TxnBytesHex: "deadbeef"}, want: RequestModeForeign},
		{name: "passthrough mode", request: SignRequest{SignedTxnHex: "cafebabe"}, want: RequestModePassthrough},
		{name: "conflict", request: SignRequest{AuthAddress: "ADDR", TxnBytesHex: "deadbeef", SignedTxnHex: "cafebabe"}, wantErr: "cannot specify both sign fields"},
		{name: "auth only", request: SignRequest{AuthAddress: "ADDR"}, wantErr: "txn_bytes_hex is required for sign mode"},
		{name: "empty", request: SignRequest{}, wantErr: "must specify either sign fields"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.request.Mode()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Mode() error = %v", err)
				}
				if got != tt.want {
					t.Fatalf("Mode() = %q, want %q", got, tt.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Mode() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestGroupSignRequestValidate(t *testing.T) {
	tests := []struct {
		name    string
		request GroupSignRequest
		wantErr string
	}{
		{name: "sign mode", request: GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef"}}}},
		{name: "client request ID", request: GroupSignRequest{RequestID: "cli.abc_123:test", Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef"}}}},
		{name: "mixed sign and foreign", request: GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef"}, {TxnBytesHex: "cafebabe"}}}},
		{name: "foreign native pq", request: GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef"}, {TxnBytesHex: "cafebabe", PQScheme: "f1"}}}},
		{name: "foreign LogicSig resources", request: GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef"}, {TxnBytesHex: "cafebabe", LsigResources: &LogicSigResourceUsage{ProgramBytes: 1_800, ArgumentBytes: 1_423, MaxOpcodeCost: 20_000}}}}},
		{name: "passthrough mode", request: GroupSignRequest{Requests: []SignRequest{{SignedTxnHex: "cafebabe"}}}},
		{name: "all passthrough mode", request: GroupSignRequest{Requests: []SignRequest{{SignedTxnHex: "cafebabe"}, {SignedTxnHex: "feedface"}}}},
		{
			name:    "conflicting sign and passthrough",
			request: GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef", SignedTxnHex: "cafebabe"}}},
			wantErr: "transaction 1: cannot specify both sign fields",
		},
		{name: "auth without txn bytes", request: GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR"}}}, wantErr: "transaction 1: txn_bytes_hex is required for sign mode"},
		{name: "pq hint on sign mode", request: GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef", PQScheme: "f1"}}}, wantErr: "pq_scheme is allowed only for foreign"},
		{name: "resources on sign mode", request: GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef", LsigResources: &LogicSigResourceUsage{ProgramBytes: 1, MaxOpcodeCost: 1}}}}, wantErr: "lsig_resources is allowed only for foreign"},
		{name: "resources and pq", request: GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef"}, {TxnBytesHex: "cafebabe", PQScheme: "f1", LsigResources: &LogicSigResourceUsage{ProgramBytes: 1, MaxOpcodeCost: 1}}}}, wantErr: "cannot specify both pq_scheme and lsig_resources"},
		{name: "invalid resources", request: GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef"}, {TxnBytesHex: "cafebabe", LsigResources: &LogicSigResourceUsage{ProgramBytes: 16_001, MaxOpcodeCost: 1}}}}, wantErr: "program_bytes 16001 exceeds"},
		{name: "empty entry", request: GroupSignRequest{Requests: []SignRequest{{}}}, wantErr: "transaction 1: must specify either sign fields"},
		{name: "empty request array", request: GroupSignRequest{}, wantErr: "requests array is empty"},
		{name: "invalid client request ID", request: GroupSignRequest{RequestID: "bad id", Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef"}}}, wantErr: "request_id contains invalid character"},
		{name: "all foreign", request: GroupSignRequest{Requests: []SignRequest{{TxnBytesHex: "deadbeef"}}}, wantErr: "no signable transactions: all entries are foreign"},
		{
			name: "mixed passthrough and foreign",
			request: GroupSignRequest{Requests: []SignRequest{
				{SignedTxnHex: "cafebabe"},
				{TxnBytesHex: "deadbeef"},
			}},
			wantErr: "cannot mix passthrough and foreign transactions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestCancelSignRequestValidate(t *testing.T) {
	tests := []struct {
		name    string
		request CancelSignRequest
		wantErr string
	}{
		{name: "valid", request: CancelSignRequest{RequestID: "cli.abc_123:test"}},
		{name: "missing", request: CancelSignRequest{}, wantErr: "request_id is required"},
		{name: "invalid", request: CancelSignRequest{RequestID: "bad id"}, wantErr: "request_id contains invalid character"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestSignCancelStateValues(t *testing.T) {
	if SignCancelStateCanceled != "canceled" {
		t.Fatalf("SignCancelStateCanceled = %q, want canceled", SignCancelStateCanceled)
	}
	if SignCancelStateNotFound != "not_found" {
		t.Fatalf("SignCancelStateNotFound = %q, want not_found", SignCancelStateNotFound)
	}
}
