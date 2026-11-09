// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSignRequestRejectsRetiredLogicSigSize(t *testing.T) {
	var request GroupSignRequest
	err := json.Unmarshal([]byte(`{"requests":[{"txn_bytes_hex":"deadbeef","lsig_size":4000}]}`), &request)
	if err == nil || !strings.Contains(err.Error(), `field "lsig_size" is unsupported`) {
		t.Fatalf("json.Unmarshal() error = %v, want retired lsig_size rejection", err)
	}
}

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
		{name: "passthrough LogicSig resources", request: GroupSignRequest{Requests: []SignRequest{{SignedTxnHex: "cafebabe", LsigResources: &LogicSigResourceUsage{ProgramBytes: 1_800, ArgumentBytes: 1_423, MaxOpcodeCost: 20_000}}}}},
		{name: "all passthrough mode", request: GroupSignRequest{Requests: []SignRequest{{SignedTxnHex: "cafebabe"}, {SignedTxnHex: "feedface"}}}},
		{
			name:    "conflicting sign and passthrough",
			request: GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef", SignedTxnHex: "cafebabe"}}},
			wantErr: "transaction 1: cannot specify both sign fields",
		},
		{name: "auth without txn bytes", request: GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR"}}}, wantErr: "transaction 1: txn_bytes_hex is required for sign mode"},
		{name: "pq hint on sign mode", request: GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef", PQScheme: "f1"}}}, wantErr: "pq_scheme is allowed only for foreign"},
		{name: "unsupported pq hint", request: GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef"}, {TxnBytesHex: "cafebabe", PQScheme: "f2"}}}, wantErr: `unsupported pq_scheme "f2"`},
		{name: "resources on sign mode", request: GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "deadbeef", LsigResources: &LogicSigResourceUsage{ProgramBytes: 1, MaxOpcodeCost: 1}}}}, wantErr: "lsig_resources is allowed only for foreign or passthrough"},
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

// The ABI method label is shown to the operator, and a method signature is
// always printable ASCII, so every request that carries one refuses anything
// else.
func TestAppCallMethodMustBePrintableASCII(t *testing.T) {
	const want = "app_call_info.method must be printable ASCII"
	for _, method := range []string{"x\x1b[2J(uint64)void", "pay\n(uint64)void", "pay\r(uint64)void", "pay\u202e(uint64)void", "pay\x7f()void", "pay\xff()void"} {
		info := &AppCallInfo{Mode: "abi", Method: method}
		validate := map[string]func() error{
			"sign": func() error {
				return GroupSignRequest{Requests: []SignRequest{{AuthAddress: "A", TxnBytesHex: "5458aa", AppCallInfo: info}}}.Validate()
			},
			"foreign": func() error {
				return GroupSignRequest{Requests: []SignRequest{
					{AuthAddress: "A", TxnBytesHex: "5458aa"},
					{TxnBytesHex: "5458bb", AppCallInfo: info},
				}}.Validate()
			},
			"component target": func() error {
				return ComponentRequest{GroupBytesHex: []string{"5458aa"}, Targets: []ComponentTarget{{
					TargetIndex: 0, Kind: ComponentTargetKindCosigner, ComponentKey: "COSIGNER", AppCallInfo: info,
				}}}.Validate()
			},
			"component contextual position": func() error {
				return ComponentRequest{
					GroupBytesHex:       []string{"5458aa", "5458bb"},
					Targets:             []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindCosigner, ComponentKey: "COSIGNER"}},
					ContextualPositions: []ComponentContextPosition{{TargetIndex: 1, AppCallInfo: info}},
				}.Validate()
			},
			"rotating sign": func() error {
				return RotatingSignRequest{Account: "A", Transactions: []string{"5458aa"}, AppCallInfo: info}.Validate()
			},
		}
		for name, check := range validate {
			if err := check(); err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s with method %q: Validate() error = %v, want %q", name, method, err, want)
			}
		}
	}

	ok := &AppCallInfo{Mode: "abi", Method: "transfer(address,uint64,(byte[],string))bool"}
	if err := (GroupSignRequest{Requests: []SignRequest{{AuthAddress: "A", TxnBytesHex: "5458aa", AppCallInfo: ok}}}).Validate(); err != nil {
		t.Fatalf("a printable method signature was refused: %v", err)
	}
}

// A contextual position that names one of the signer's own accounts is a
// bounded-base concept: the signer sizes it from its records, so it takes no
// hint, and a cosigner request refuses the fields outright.
func TestComponentRequestContextualPositionRules(t *testing.T) {
	request := func(kind ComponentTargetKind, position ComponentContextPosition) ComponentRequest {
		target := ComponentTarget{TargetIndex: 0, Kind: kind}
		if kind == ComponentTargetKindBoundedBase {
			target.AuthAddress = "BOUNDED"
		} else {
			target.ComponentKey = "witness-key"
		}
		position.TargetIndex = 1
		return ComponentRequest{
			GroupBytesHex:       []string{"5458a1", "5458a2"},
			Targets:             []ComponentTarget{target},
			ContextualPositions: []ComponentContextPosition{position},
		}
	}
	hint := &LogicSigResourceUsage{ProgramBytes: 100, MaxOpcodeCost: 700}
	for name, tc := range map[string]struct {
		kind     ComponentTargetKind
		position ComponentContextPosition
		wantErr  string
	}{
		"held account":                  {ComponentTargetKindBoundedBase, ComponentContextPosition{AuthAddress: "HELD", LsigArgs: map[string]string{"a": "bb"}}, ""},
		"another party, hinted":         {ComponentTargetKindBoundedBase, ComponentContextPosition{PQScheme: PQSchemeFalcon1024}, ""},
		"another party, unhinted":       {ComponentTargetKindCosigner, ComponentContextPosition{}, ""},
		"held account with pq hint":     {ComponentTargetKindBoundedBase, ComponentContextPosition{AuthAddress: "HELD", PQScheme: PQSchemeFalcon1024}, "lsig_resources and pq_scheme are allowed only without auth_address"},
		"held account with size hint":   {ComponentTargetKindBoundedBase, ComponentContextPosition{AuthAddress: "HELD", LsigResources: hint}, "lsig_resources and pq_scheme are allowed only without auth_address"},
		"lsig_args without account":     {ComponentTargetKindBoundedBase, ComponentContextPosition{LsigArgs: map[string]string{"a": "bb"}}, "lsig_args requires auth_address"},
		"account on a cosigner request": {ComponentTargetKindCosigner, ComponentContextPosition{AuthAddress: "HELD"}, "allowed only on a bounded-base request"},
	} {
		err := request(tc.kind, tc.position).Validate()
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("%s: unexpected error: %v", name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "contextual position 1: ") || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.wantErr)
		}
	}
}
