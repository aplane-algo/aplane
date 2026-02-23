// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package signing

import (
	"encoding/base64"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
)

func TestFormatFailedAt(t *testing.T) {
	tests := []struct {
		name string
		path []uint64
		want string
	}{
		{"empty", nil, "unknown"},
		{"single txn index 0", []uint64{0}, "transaction 1"},
		{"single txn index 2", []uint64{2}, "transaction 3"},
		{"with inner", []uint64{0, 1}, "transaction 1 → inner 2"},
		{"nested inner", []uint64{1, 0, 2}, "transaction 2 → inner 1 → inner 3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatFailedAt(tt.path)
			if got != tt.want {
				t.Errorf("formatFailedAt(%v) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestFormatLogEntry(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"empty", nil, "(empty)"},
		{"printable", []byte("hello"), `"hello"`},
		{"binary", []byte{0x00, 0x01, 0x02}, "(3 bytes) 0x000102"},
		{"mixed", []byte("hello\x00"), "(6 bytes) 0x68656c6c6f00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatLogEntry(tt.data)
			if got != tt.want {
				t.Errorf("formatLogEntry(%v) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}

func TestFormatAvmValue(t *testing.T) {
	tests := []struct {
		name string
		v    models.AvmValue
		want string
	}{
		{"uint", models.AvmValue{Type: 2, Uint: 42}, "42"},
		{"bytes printable", models.AvmValue{Type: 1, Bytes: []byte("abc")}, `"abc"`},
		{"bytes binary", models.AvmValue{Type: 1, Bytes: []byte{0xff, 0x00}}, "0xff00"},
		{"bytes empty", models.AvmValue{Type: 1, Bytes: nil}, "0"},
		{"zero type", models.AvmValue{Type: 0, Uint: 0}, "0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatAvmValue(tt.v)
			if got != tt.want {
				t.Errorf("formatAvmValue(%+v) = %q, want %q", tt.v, got, tt.want)
			}
		})
	}
}

func TestFormatEvalDelta(t *testing.T) {
	// EvalDelta.Key and EvalDelta.Bytes are base64-encoded in the REST API
	tests := []struct {
		name string
		kv   models.EvalDeltaKeyValue
		want string
	}{
		{
			"set uint",
			models.EvalDeltaKeyValue{
				Key:   base64.StdEncoding.EncodeToString([]byte("counter")),
				Value: models.EvalDelta{Action: 2, Uint: 100},
			},
			`set "counter" = 100`,
		},
		{
			"set printable bytes",
			models.EvalDeltaKeyValue{
				Key:   base64.StdEncoding.EncodeToString([]byte("name")),
				Value: models.EvalDelta{Action: 1, Bytes: base64.StdEncoding.EncodeToString([]byte("alice"))},
			},
			`set "name" = "alice"`,
		},
		{
			"set binary bytes",
			models.EvalDeltaKeyValue{
				Key:   base64.StdEncoding.EncodeToString([]byte("hash")),
				Value: models.EvalDelta{Action: 1, Bytes: base64.StdEncoding.EncodeToString([]byte{0xde, 0xad})},
			},
			`set "hash" = 0xdead`,
		},
		{
			"delete",
			models.EvalDeltaKeyValue{
				Key:   base64.StdEncoding.EncodeToString([]byte("old")),
				Value: models.EvalDelta{Action: 3},
			},
			`delete "old"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatEvalDelta(tt.kv)
			if got != tt.want {
				t.Errorf("formatEvalDelta() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeStateKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want string
	}{
		{"empty", "", `""`},
		{"base64 printable", base64.StdEncoding.EncodeToString([]byte("counter")), `"counter"`},
		{"base64 binary", base64.StdEncoding.EncodeToString([]byte{0xff, 0x01}), "0xff01"},
		{"not base64", "not!valid!b64$$$", `"not!valid!b64$$$"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeStateKey(tt.key)
			if got != tt.want {
				t.Errorf("decodeStateKey(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestFormatKeyBytes(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"empty", nil, `""`},
		{"printable", []byte("key"), `"key"`},
		{"binary", []byte{0xab, 0xcd}, "0xabcd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatKeyBytes(tt.data)
			if got != tt.want {
				t.Errorf("formatKeyBytes(%v) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}

func TestIsPrintable(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"empty", nil, false},
		{"ascii", []byte("hello world"), true},
		{"with null", []byte("hello\x00"), false},
		{"with newline", []byte("hello\n"), false},
		{"space", []byte(" "), true},
		{"tilde", []byte("~"), true},
		{"control char", []byte{0x1f}, false},
		{"high byte", []byte{0x80}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPrintable(tt.data)
			if got != tt.want {
				t.Errorf("isPrintable(%v) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

func TestShortAddr(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{"short", "ABCD", "ABCD"},
		{"exactly 12", "ABCDEFGHIJKL", "ABCDEFGHIJKL"},
		{"long", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUV", "ABCDEFGH...STUV"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shortAddr(tt.addr)
			if got != tt.want {
				t.Errorf("shortAddr(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

func TestFormatAppStateOp(t *testing.T) {
	tests := []struct {
		name string
		op   models.ApplicationStateOperation
		want string
	}{
		{
			"global write uint",
			models.ApplicationStateOperation{
				AppStateType: "g", Operation: "w",
				Key:      []byte("count"),
				NewValue: models.AvmValue{Type: 2, Uint: 5},
			},
			`global write "count" = 5`,
		},
		{
			"local delete",
			models.ApplicationStateOperation{
				AppStateType: "l", Operation: "d",
				Key: []byte("temp"),
			},
			`local delete "temp"`,
		},
		{
			"box write bytes",
			models.ApplicationStateOperation{
				AppStateType: "b", Operation: "w",
				Key:      []byte("data"),
				NewValue: models.AvmValue{Type: 1, Bytes: []byte{0xab}},
			},
			`box write "data" = 0xab`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatAppStateOp(tt.op)
			if got != tt.want {
				t.Errorf("formatAppStateOp() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatExecTrace_Empty(t *testing.T) {
	// Empty trace should produce no output
	trace := models.SimulationTransactionExecTrace{}
	got := formatExecTrace(trace, "  ")
	if got != "" {
		t.Errorf("formatExecTrace(empty) = %q, want empty", got)
	}
}

func TestFormatExecTrace_ApprovalProgram(t *testing.T) {
	trace := models.SimulationTransactionExecTrace{
		ApprovalProgramTrace: []models.SimulationOpcodeTraceUnit{
			{Pc: 0},
			{Pc: 1},
			{Pc: 5},
		},
	}
	got := formatExecTrace(trace, "")
	want := "Approval program: 3 opcodes executed\n"
	if got != want {
		t.Errorf("formatExecTrace(approval) = %q, want %q", got, want)
	}
}

func TestFormatExecTrace_ClearStateRollback(t *testing.T) {
	trace := models.SimulationTransactionExecTrace{
		ClearStateProgramTrace:  []models.SimulationOpcodeTraceUnit{{Pc: 0}},
		ClearStateRollback:      true,
		ClearStateRollbackError: "assert failed",
	}
	got := formatExecTrace(trace, "")
	if got == "" {
		t.Fatal("expected non-empty output for clear-state rollback")
	}
	if !contains(got, "Rolled back: assert failed") {
		t.Errorf("expected rollback error in output, got: %q", got)
	}
}

func TestFormatExecTrace_LogicSig(t *testing.T) {
	trace := models.SimulationTransactionExecTrace{
		LogicSigTrace: []models.SimulationOpcodeTraceUnit{
			{Pc: 0}, {Pc: 1},
		},
	}
	got := formatExecTrace(trace, "")
	want := "LogicSig: 2 opcodes executed\n"
	if got != want {
		t.Errorf("formatExecTrace(logicsig) = %q, want %q", got, want)
	}
}

func TestFormatTxnDetails_Empty(t *testing.T) {
	// A result with no interesting fields should produce empty string
	result := models.SimulateTransactionResult{}
	got := formatTxnDetails(0, result)
	if got != "" {
		t.Errorf("formatTxnDetails(empty) = %q, want empty", got)
	}
}

func TestFormatTxnDetails_WithLogs(t *testing.T) {
	result := models.SimulateTransactionResult{
		AppBudgetConsumed: 50,
		TxnResult: models.PendingTransactionResponse{
			Logs: [][]byte{[]byte("hello")},
		},
	}
	got := formatTxnDetails(0, result)
	if got == "" {
		t.Fatal("expected non-empty output")
	}
	if !contains(got, "Txn 1:") {
		t.Errorf("expected 1-based txn header, got: %q", got)
	}
	if !contains(got, `"hello"`) {
		t.Errorf("expected log entry in output, got: %q", got)
	}
	if !contains(got, "App budget consumed: 50") {
		t.Errorf("expected budget info, got: %q", got)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
