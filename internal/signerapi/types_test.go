// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerapi

import (
	"strings"
	"testing"
)

func TestGroupSignRequestValidate(t *testing.T) {
	tests := []struct {
		name    string
		request GroupSignRequest
		wantErr string
	}{
		{name: "sign mode", request: GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef"}}}},
		{name: "client request ID", request: GroupSignRequest{RequestID: "cli.abc_123:test", Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef"}}}},
		{name: "mixed sign and foreign", request: GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef"}, {TxnBytesHex: "cafebabe"}}}},
		{name: "passthrough mode", request: GroupSignRequest{Requests: []SignRequest{{SignedTxnHex: "cafebabe"}}}},
		{
			name:    "conflicting sign and passthrough",
			request: GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef", SignedTxnHex: "cafebabe"}}},
			wantErr: "transaction 1: cannot specify both sign fields",
		},
		{name: "auth without txn bytes", request: GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR"}}}, wantErr: "transaction 1: txn_bytes_hex is required for sign mode"},
		{name: "empty request", request: GroupSignRequest{Requests: []SignRequest{{}}}, wantErr: "transaction 1: must specify either sign fields"},
		{name: "all foreign", request: GroupSignRequest{Requests: []SignRequest{{TxnBytesHex: "deadbeef"}}}, wantErr: "no signable transactions: all entries are foreign"},
		{name: "empty request array", request: GroupSignRequest{}, wantErr: "requests array is empty"},
		{name: "invalid client request ID", request: GroupSignRequest{RequestID: "bad id", Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef"}}}, wantErr: "request_id contains invalid character"},
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
