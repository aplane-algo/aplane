// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

import (
	"testing"

	"github.com/dop251/goja"

	"github.com/aplane-algo/aplane/internal/engine"
)

// TestAlgoFunc tests the algo() helper that converts ALGO to microAlgos.
func TestAlgoFunc(t *testing.T) {
	vm := goja.New()
	algoFn := makeAlgoFunc(vm)

	tests := []struct {
		name      string
		input     interface{}
		want      uint64
		wantPanic bool
		panicMsg  string
	}{
		{
			name:  "whole number",
			input: 1.0,
			want:  1_000_000,
		},
		{
			name:  "fractional",
			input: 1.5,
			want:  1_500_000,
		},
		{
			name:  "small fraction",
			input: 0.000001,
			want:  1,
		},
		{
			name:  "zero",
			input: 0.0,
			want:  0,
		},
		{
			name:  "large number",
			input: 1000.0,
			want:  1_000_000_000,
		},
		{
			name:  "integer input",
			input: 5,
			want:  5_000_000,
		},
		{
			name:      "negative number",
			input:     -1.0,
			wantPanic: true,
			panicMsg:  "algo() cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := goja.FunctionCall{
				Arguments: []goja.Value{vm.ToValue(tt.input)},
			}

			if tt.wantPanic {
				defer func() {
					r := recover()
					if r == nil {
						t.Errorf("expected panic but got none")
						return
					}
					if v, ok := r.(goja.Value); ok {
						if v.String() != tt.panicMsg {
							t.Errorf("panic message = %q, want %q", v.String(), tt.panicMsg)
						}
					}
				}()
			}

			result := algoFn(call)

			if tt.wantPanic {
				t.Errorf("expected panic but function returned normally")
				return
			}

			// Goja exports numbers as int64, so handle the conversion
			exported := result.Export()
			var got uint64
			switch v := exported.(type) {
			case int64:
				got = uint64(v)
			case uint64:
				got = v
			default:
				t.Errorf("algo(%v) returned unexpected type %T", tt.input, exported)
				return
			}
			if got != tt.want {
				t.Errorf("algo(%v) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// TestAlgoFuncNoArgs tests algo() panics when called with no arguments.
func TestAlgoFuncNoArgs(t *testing.T) {
	vm := goja.New()
	algoFn := makeAlgoFunc(vm)

	defer func() {
		r := recover()
		if r == nil {
			t.Errorf("expected panic but got none")
			return
		}
		if v, ok := r.(goja.Value); ok {
			want := "algo() requires a number argument"
			if v.String() != want {
				t.Errorf("panic message = %q, want %q", v.String(), want)
			}
		}
	}()

	call := goja.FunctionCall{Arguments: []goja.Value{}}
	algoFn(call)
	t.Errorf("expected panic but function returned normally")
}

// TestMicroalgosFunc tests the microalgos() helper.
func TestMicroalgosFunc(t *testing.T) {
	vm := goja.New()
	microalgosFn := makeMicroalgosFunc(vm)

	tests := []struct {
		name      string
		input     interface{}
		want      uint64
		wantPanic bool
		panicMsg  string
	}{
		{
			name:  "integer",
			input: 1000000,
			want:  1000000,
		},
		{
			name:  "zero",
			input: 0,
			want:  0,
		},
		{
			name:  "large value",
			input: uint64(10_000_000_000),
			want:  10_000_000_000,
		},
		{
			name:      "negative",
			input:     -100,
			wantPanic: true,
			panicMsg:  "value cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := goja.FunctionCall{
				Arguments: []goja.Value{vm.ToValue(tt.input)},
			}

			if tt.wantPanic {
				defer func() {
					r := recover()
					if r == nil {
						t.Errorf("expected panic but got none")
						return
					}
					if v, ok := r.(goja.Value); ok {
						if v.String() != tt.panicMsg {
							t.Errorf("panic message = %q, want %q", v.String(), tt.panicMsg)
						}
					}
				}()
			}

			result := microalgosFn(call)

			if tt.wantPanic {
				t.Errorf("expected panic but function returned normally")
				return
			}

			// Goja exports numbers as int64, so handle the conversion
			exported := result.Export()
			var got uint64
			switch v := exported.(type) {
			case int64:
				got = uint64(v)
			case uint64:
				got = v
			default:
				t.Errorf("microalgos(%v) returned unexpected type %T", tt.input, exported)
				return
			}
			if got != tt.want {
				t.Errorf("microalgos(%v) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// TestMicroalgosFuncNoArgs tests microalgos() panics when called with no arguments.
func TestMicroalgosFuncNoArgs(t *testing.T) {
	vm := goja.New()
	microalgosFn := makeMicroalgosFunc(vm)

	defer func() {
		r := recover()
		if r == nil {
			t.Errorf("expected panic but got none")
			return
		}
		if v, ok := r.(goja.Value); ok {
			want := "microalgos() requires a number argument"
			if v.String() != want {
				t.Errorf("panic message = %q, want %q", v.String(), want)
			}
		}
	}()

	call := goja.FunctionCall{Arguments: []goja.Value{}}
	microalgosFn(call)
	t.Errorf("expected panic but function returned normally")
}

// TestToUint64 tests the toUint64 Goja helper.
func TestToUint64(t *testing.T) {
	vm := goja.New()

	tests := []struct {
		name      string
		input     interface{}
		want      uint64
		wantPanic bool
	}{
		{
			name:  "int64 positive",
			input: int64(42),
			want:  42,
		},
		{
			name:  "int64 zero",
			input: int64(0),
			want:  0,
		},
		{
			name:  "float64 positive",
			input: float64(123.0),
			want:  123,
		},
		{
			name:  "float64 with decimal truncates",
			input: float64(99.9),
			want:  99,
		},
		{
			name:  "int positive",
			input: 100,
			want:  100,
		},
		{
			name:  "uint64",
			input: uint64(999),
			want:  999,
		},
		{
			name:      "int64 negative",
			input:     int64(-1),
			wantPanic: true,
		},
		{
			name:      "float64 negative",
			input:     float64(-0.5),
			wantPanic: true,
		},
		{
			name:      "int negative",
			input:     -50,
			wantPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := vm.ToValue(tt.input)

			if tt.wantPanic {
				defer func() {
					r := recover()
					if r == nil {
						t.Errorf("expected panic but got none")
					}
				}()
			}

			got := toUint64(vm, v)

			if tt.wantPanic {
				t.Errorf("expected panic but function returned normally")
				return
			}

			if got != tt.want {
				t.Errorf("toUint64(%v) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// TestToUint64Interface tests the toUint64Interface helper.
func TestToUint64Interface(t *testing.T) {
	tests := []struct {
		name    string
		input   interface{}
		want    uint64
		wantErr bool
		errMsg  string
	}{
		{
			name:  "int64 positive",
			input: int64(42),
			want:  42,
		},
		{
			name:  "int64 zero",
			input: int64(0),
			want:  0,
		},
		{
			name:  "float64 positive",
			input: float64(123.0),
			want:  123,
		},
		{
			name:  "float64 truncates",
			input: float64(99.9),
			want:  99,
		},
		{
			name:  "int positive",
			input: 100,
			want:  100,
		},
		{
			name:  "uint64",
			input: uint64(999),
			want:  999,
		},
		{
			name:    "int64 negative",
			input:   int64(-1),
			wantErr: true,
			errMsg:  "value cannot be negative",
		},
		{
			name:    "float64 negative",
			input:   float64(-0.5),
			wantErr: true,
			errMsg:  "value cannot be negative",
		},
		{
			name:    "int negative",
			input:   -50,
			wantErr: true,
			errMsg:  "value cannot be negative",
		},
		{
			name:    "string type",
			input:   "not a number",
			wantErr: true,
			errMsg:  "unsupported type for uint64 conversion: string",
		},
		{
			name:    "nil",
			input:   nil,
			wantErr: true,
			errMsg:  "unsupported type for uint64 conversion: <nil>",
		},
		{
			name:    "slice",
			input:   []int{1, 2, 3},
			wantErr: true,
			errMsg:  "unsupported type for uint64 conversion: []int",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toUint64Interface(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if err.Error() != tt.errMsg {
					t.Errorf("error = %q, want %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("toUint64Interface(%v) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// TestParseTxnOptions tests the parseTxnOptions helper via JS runtime.
func TestParseTxnOptions(t *testing.T) {
	vm := goja.New()
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	api := NewAPI(eng, false, nil)
	api.runtime = vm

	tests := []struct {
		name      string
		args      []goja.Value
		argIndex  int
		wantFee   uint64
		wantFlat  bool
		wantWait  bool
		wantNote  string
		wantPanic bool
	}{
		{
			name:     "no options arg",
			args:     []goja.Value{vm.ToValue("from"), vm.ToValue("to")},
			argIndex: 2,
			wantWait: true,
		},
		{
			name:     "undefined options",
			args:     []goja.Value{vm.ToValue("from"), vm.ToValue("to"), goja.Undefined()},
			argIndex: 2,
			wantWait: true,
		},
		{
			name:     "null options",
			args:     []goja.Value{vm.ToValue("from"), vm.ToValue("to"), goja.Null()},
			argIndex: 2,
			wantWait: true,
		},
		{
			name: "fee only",
			args: []goja.Value{vm.ToValue("from"), vm.ToValue("to"),
				vm.ToValue(map[string]interface{}{"fee": 2000})},
			argIndex: 2,
			wantFee:  2000,
			wantFlat: true,
			wantWait: true,
		},
		{
			name: "wait false",
			args: []goja.Value{vm.ToValue("from"), vm.ToValue("to"),
				vm.ToValue(map[string]interface{}{"wait": false})},
			argIndex: 2,
			wantWait: false,
		},
		{
			name: "note",
			args: []goja.Value{vm.ToValue("from"), vm.ToValue("to"),
				vm.ToValue(map[string]interface{}{"note": "hello"})},
			argIndex: 2,
			wantWait: true,
			wantNote: "hello",
		},
		{
			name: "all options",
			args: []goja.Value{vm.ToValue("from"), vm.ToValue("to"),
				vm.ToValue(map[string]interface{}{"fee": 3000, "wait": false, "note": "test"})},
			argIndex: 2,
			wantFee:  3000,
			wantFlat: true,
			wantWait: false,
			wantNote: "test",
		},
		{
			name: "negative fee panics",
			args: []goja.Value{vm.ToValue("from"), vm.ToValue("to"),
				vm.ToValue(map[string]interface{}{"fee": -1})},
			argIndex:  2,
			wantPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := goja.FunctionCall{Arguments: tt.args}

			if tt.wantPanic {
				defer func() {
					r := recover()
					if r == nil {
						t.Error("expected panic but got none")
					}
				}()
			}

			opts := api.parseTxnOptions(call, tt.argIndex, "test()")

			if tt.wantPanic {
				t.Error("expected panic but function returned normally")
				return
			}

			if opts.Fee != tt.wantFee {
				t.Errorf("Fee = %d, want %d", opts.Fee, tt.wantFee)
			}
			if opts.UseFlatFee != tt.wantFlat {
				t.Errorf("UseFlatFee = %v, want %v", opts.UseFlatFee, tt.wantFlat)
			}
			if opts.Wait != tt.wantWait {
				t.Errorf("Wait = %v, want %v", opts.Wait, tt.wantWait)
			}
			if opts.Note != tt.wantNote {
				t.Errorf("Note = %q, want %q", opts.Note, tt.wantNote)
			}
		})
	}
}

// TestOptOutOverloadParsing tests parseOptOutArgs which handles optOut's
// overloaded argument parsing. This calls the real method used by jsOptOut.
func TestOptOutOverloadParsing(t *testing.T) {
	vm := goja.New()
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	api := NewAPI(eng, false, nil)
	api.runtime = vm

	tests := []struct {
		name      string
		args      []goja.Value
		wantClose string
		wantFee   uint64
		wantFlat  bool
		wantWait  bool
	}{
		{
			name:     "2 args — no closeTo, defaults",
			args:     []goja.Value{vm.ToValue("acct"), vm.ToValue(123)},
			wantWait: true,
		},
		{
			name:      "3 args — closeTo string, no options",
			args:      []goja.Value{vm.ToValue("acct"), vm.ToValue(123), vm.ToValue("receiver")},
			wantClose: "receiver",
			wantWait:  true,
		},
		{
			name: "3 args — options map (no closeTo)",
			args: []goja.Value{vm.ToValue("acct"), vm.ToValue(123),
				vm.ToValue(map[string]interface{}{"fee": 2000, "wait": false})},
			wantFee:  2000,
			wantFlat: true,
			wantWait: false,
		},
		{
			name: "4 args — closeTo string + options",
			args: []goja.Value{vm.ToValue("acct"), vm.ToValue(123), vm.ToValue("receiver"),
				vm.ToValue(map[string]interface{}{"fee": 3000, "wait": false})},
			wantClose: "receiver",
			wantFee:   3000,
			wantFlat:  true,
			wantWait:  false,
		},
		{
			name: "4 args — null placeholder + options",
			args: []goja.Value{vm.ToValue("acct"), vm.ToValue(123), goja.Null(),
				vm.ToValue(map[string]interface{}{"fee": 5000, "wait": false})},
			wantFee:  5000,
			wantFlat: true,
			wantWait: false,
		},
		{
			name: "4 args — undefined placeholder + options",
			args: []goja.Value{vm.ToValue("acct"), vm.ToValue(123), goja.Undefined(),
				vm.ToValue(map[string]interface{}{"fee": 4000})},
			wantFee:  4000,
			wantFlat: true,
			wantWait: true,
		},
		{
			name:     "3 args — null placeholder, no arg3",
			args:     []goja.Value{vm.ToValue("acct"), vm.ToValue(123), goja.Null()},
			wantWait: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := goja.FunctionCall{Arguments: tt.args}
			closeTo, opts := api.parseOptOutArgs(call)
			if closeTo != tt.wantClose {
				t.Errorf("closeTo = %q, want %q", closeTo, tt.wantClose)
			}
			if opts.Fee != tt.wantFee {
				t.Errorf("Fee = %d, want %d", opts.Fee, tt.wantFee)
			}
			if opts.UseFlatFee != tt.wantFlat {
				t.Errorf("UseFlatFee = %v, want %v", opts.UseFlatFee, tt.wantFlat)
			}
			if opts.Wait != tt.wantWait {
				t.Errorf("Wait = %v, want %v", opts.Wait, tt.wantWait)
			}
		})
	}
}

// TestToStringArray tests the toStringArray helper.
func TestToStringArray(t *testing.T) {
	vm := goja.New()

	tests := []struct {
		name  string
		input interface{}
		want  []string
	}{
		{
			name:  "interface slice with strings",
			input: []interface{}{"a", "b", "c"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "empty interface slice",
			input: []interface{}{},
			want:  []string{},
		},
		{
			name:  "mixed types filters non-strings",
			input: []interface{}{"a", 123, "b", true},
			want:  []string{"a", "b"},
		},
		{
			name:  "string slice",
			input: []string{"x", "y", "z"},
			want:  []string{"x", "y", "z"},
		},
		{
			name:  "nil returns nil",
			input: nil,
			want:  nil,
		},
		{
			name:  "non-array returns nil",
			input: "not an array",
			want:  nil,
		},
		{
			name:  "number returns nil",
			input: 42,
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := vm.ToValue(tt.input)
			got := toStringArray(v)

			if tt.want == nil {
				if got != nil {
					t.Errorf("toStringArray(%v) = %v, want nil", tt.input, got)
				}
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("toStringArray(%v) len = %d, want %d", tt.input, len(got), len(tt.want))
				return
			}

			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("toStringArray(%v)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}
