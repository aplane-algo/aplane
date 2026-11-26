// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

import (
	"fmt"
	"math"
	"reflect"
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
			name:      "float64 with decimal rejected (no silent truncation)",
			input:     float64(99.9),
			wantPanic: true,
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
			name:      "float64 out of range",
			input:     float64(1e36),
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
			name:    "float64 fractional rejected (no silent truncation)",
			input:   float64(99.9),
			wantErr: true,
			errMsg:  "value must be a whole number of base units (got 99.9)",
		},
		{
			name:    "float64 out of range",
			input:   float64(1e36),
			wantErr: true,
			errMsg:  "value 1e+36 is too large",
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
			errMsg:  `"not a number" is not a whole number in plain decimal`,
		},
		{
			name:    "nil",
			input:   nil,
			wantErr: true,
			errMsg:  "a number is needed, got null or undefined",
		},
		{
			name:    "slice",
			input:   []int{1, 2, 3},
			wantErr: true,
			errMsg:  "a number is needed, got a []int",
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

// TestParseTxnOptions tests the parseNotedTxnOptions helper, which reads
// parseTxnOptions' {fee, wait, lsigArgs} and a note, via JS runtime.
func TestParseTxnOptions(t *testing.T) {
	vm := goja.New()
	eng := engine.NewEngine("testnet")
	api := NewAPI(eng, func(string) {})
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

			opts := api.parseNotedTxnOptions(call, tt.argIndex, "test()")

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
	eng := engine.NewEngine("testnet")
	api := NewAPI(eng, func(string) {})
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

// TestStringArray: an array of strings is read as given; anything else is an
// error. A non-string entry is never dropped, because that would move every
// entry after it.
func TestStringArray(t *testing.T) {
	accepted := []struct {
		name  string
		input interface{}
		want  []string
	}{
		{"strings", []interface{}{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"empty", []interface{}{}, []string{}},
		{"string slice", []string{"x", "y"}, []string{"x", "y"}},
	}
	for _, tt := range accepted {
		got, err := stringArray(tt.input)
		if err != nil || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: stringArray() = %v, %v; want %v", tt.name, got, err, tt.want)
		}
	}
	refused := map[string]interface{}{
		"a number among strings":  []interface{}{"a", int64(123), "b"},
		"a boolean among strings": []interface{}{"a", true},
		"null among strings":      []interface{}{"a", nil, "b"},
		"nil":                     nil,
		"a string":                "not an array",
		"a number":                int64(42),
	}
	for name, input := range refused {
		if got, err := stringArray(input); err == nil {
			t.Errorf("%s: stringArray() = %v, want an error", name, got)
		}
	}
}

// TestToJSObjectKeepsAppStateUintsExact pins that an app-state uint past
// 2^53 reaches the script with its exact value, as a BigInt, and is accepted
// when the script passes it back, as toUint64 reads every amount and ID. A
// value JavaScript holds exactly stays a number.
func TestToJSObjectKeepsAppStateUintsExact(t *testing.T) {
	vm := goja.New()
	api := &API{runtime: vm}
	const pastSafe = uint64(1)<<53 + 1
	const pastInt64 = uint64(math.MaxInt64) + 2
	want := []uint64{pastSafe, math.MaxInt64, pastInt64, math.MaxUint64}
	state := engine.AppGlobalStateResult{AppID: pastSafe}
	for _, u := range want {
		state.GlobalState = append(state.GlobalState, engine.AppStateEntry{
			KeyBase64: "aw==", Value: engine.AppStateValue{Type: "uint", Uint: u},
		})
	}
	if err := vm.Set("state", api.toJSObject(&state)); err != nil {
		t.Fatal(err)
	}

	check := func(expr string, want uint64) {
		t.Helper()
		v, err := vm.RunString(expr)
		if err != nil {
			t.Fatalf("%s: %v", expr, err)
		}
		var got uint64
		if err := jsError(func() { got = toUint64(vm, v) }); err != nil {
			t.Errorf("%s = %v, refused when passed back: %v", expr, v, err)
			return
		}
		if got != want {
			t.Errorf("%s = %d, want %d", expr, got, want)
		}
	}
	check("state.app_id", pastSafe)
	for i, u := range want {
		check(fmt.Sprintf("state.global_state[%d].value.uint", i), u)
	}

	small := engine.AppStateValue{Type: "uint", Uint: 1<<53 - 1}
	if err := vm.Set("small", api.toJSObject(small)); err != nil {
		t.Fatal(err)
	}
	v, err := vm.RunString(`[typeof small.uint, typeof state.app_id].join(",")`)
	if err != nil {
		t.Fatal(err)
	}
	if got := v.String(); got != "number,bigint" {
		t.Errorf("types = %s, want number,bigint", got)
	}
	check("small.uint", 1<<53-1)
}

// toUint64 reads a JS value as a uint64 or throws; each throw keeps its text.
func TestToUint64ResultsAndThrows(t *testing.T) {
	vm := goja.New()
	for _, tc := range []struct{ expr, want string }{
		{"42", "42"},
		{"0", "0"},
		{"-1", "throws: value cannot be negative"},
		{"1.5", "throws: value must be a whole number of base units (got 1.5)"},
		{"NaN", "throws: value must be a finite number"},
		{"Infinity", "throws: value must be a finite number"},
		{"-0.5", "throws: value cannot be negative"},
		{"1e19", "throws: value 1e+19 is too large"},
		{"9223372036854775808", "throws: value 9.223372036854776e+18 is too large"},
		{"9007199254740993", "throws: value 9007199254740992 is past the largest whole number JavaScript holds exactly; pass a BigInt or a decimal string"},
		{"9007199254740991", "9007199254740991"},
		{"'123'", "123"},
		{"'0123'", "throws: \"0123\" is not a whole number in plain decimal"},
		{"''", "throws: \"\" is not a whole number in plain decimal"},
		{"'0x10'", "throws: \"0x10\" is not a whole number in plain decimal"},
		{"12345678901234567890n", "12345678901234567890"},
		{"123456789012345678901n", "throws: value 123456789012345678901 is too large"},
		{"-5n", "throws: value cannot be negative"},
		{"null", "throws: a number is needed, got null or undefined"},
		{"undefined", "throws: a number is needed, got null or undefined"},
		{"true", "throws: a number is needed, got a boolean"},
		{"({})", "throws: a number is needed, got an object"},
		{"[1]", "throws: a number is needed, got an array"},
	} {
		v, err := vm.RunString(tc.expr)
		if err != nil {
			t.Fatal(err)
		}
		var got uint64
		result := ""
		if err := jsError(func() { got = toUint64(vm, v) }); err != nil {
			result = "throws: " + err.Error()
		} else {
			result = fmt.Sprint(got)
		}
		if result != tc.want {
			t.Errorf("toUint64(%s) = %s, want %s", tc.expr, result, tc.want)
		}
	}
}
