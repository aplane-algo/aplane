// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

import (
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"testing"

	"github.com/dop251/goja"

	"github.com/aplane-algo/aplane/internal/appspec"
)

// abiArgsFromJS runs a JavaScript array literal through the same export and
// conversion appCall() uses, then through the ABI argument encoder.
func abiArgsFromJS(t *testing.T, script string, types ...string) ([][]byte, error) {
	t.Helper()
	value, err := goja.New().RunString(script)
	if err != nil {
		t.Fatalf("run %s: %v", script, err)
	}
	rawArgs := toInterfaceArray(value)
	if len(rawArgs) != len(types) {
		t.Fatalf("%s exported %d argument(s), want %d", script, len(rawArgs), len(types))
	}
	method := appspec.Method{Name: "m", Returns: appspec.MethodReturn{Type: "void"}}
	texts := make([]string, len(rawArgs))
	for i, raw := range rawArgs {
		method.Args = append(method.Args, appspec.MethodArg{Name: "a", Type: types[i]})
		texts[i], err = abiArgText(raw, types[i])
		if err != nil {
			return nil, err
		}
	}
	return method.EncodeArgs(texts)
}

func TestAppCallArgumentsEncodeByTheirABIType(t *testing.T) {
	cases := []struct {
		name, script, typeName, wantHex string
	}{
		{"Uint8Array as byte[]", `[new Uint8Array([1, 2, 3])]`, "byte[]", "0003010203"},
		{"number array as byte[]", `[[1, 2, 3]]`, "byte[]", "0003010203"},
		{"number array as byte[3]", `[[1, 2, 3]]`, "byte[3]", "010203"},
		{"hex text as byte[]", `["hex:010203"]`, "byte[]", "0003010203"},
		{"number as uint64", `[100]`, "uint64", "0000000000000064"},
		{"decimal text as uint64", `["100"]`, "uint64", "0000000000000064"},
		{"BigInt as uint64", `[18446744073709551615n]`, "uint64", "ffffffffffffffff"},
		{"boolean", `[true]`, "bool", "80"},
		{"number array as uint8[]", `[[1, 2, 3]]`, "uint8[]", "0003010203"},
		{"tuple with bytes", `[[7, new Uint8Array([1, 2])]]`, "(uint64,byte[])", "0000000000000007000a00020102"},
		{"text as string", `["[1 2 3]"]`, "string", "00075b31203220335d"},
		{"text that starts with json: as string", `["json:\"x\""]`, "string", "00086a736f6e3a227822"},
		{"hex text nested in a tuple", `[[7, "hex:0102"]]`, "(uint64,byte[])", "0000000000000007000a00020102"},
		{"plain text nested in a tuple", `[[7, "abcd"]]`, "(uint64,byte[])", "0000000000000007000a000461626364"},
		{"number array nested in an array", `[[[1, 2], [3]]]`, "byte[][]", "00020004000800020102000103"},
		{"string nested in a tuple", `[["hi", 1]]`, "(string,uint8)", "00030100026869"},
		{"decimal text nested in an array", `[["340282366920938463463374607431768211455"]]`, "uint128[]", "0001ffffffffffffffffffffffffffffffff"},
		{"decimal text nested in a tuple", `[[7, "100"]]`, "(uint64,uint64)", "00000000000000070000000000000064"},
	}
	for _, tc := range cases {
		encoded, err := abiArgsFromJS(t, tc.script, tc.typeName)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got := hex.EncodeToString(encoded[1]); got != tc.wantHex {
			t.Errorf("%s: encoded %s, want %s", tc.name, got, tc.wantHex)
		}
	}
}

func TestAppCallArgumentsRefuseWhatHasNoABIValue(t *testing.T) {
	cases := []struct{ name, script, typeName string }{
		{"null", `[null]`, "uint64"},
		{"undefined", `[undefined]`, "uint64"},
		{"null for bytes", `[null]`, "byte[]"},
		{"fraction for uint", `[1.5]`, "uint64"},
		{"octal-looking text", `["0100"]`, "uint64"},
		{"byte out of range", `[[1, 256]]`, "byte[]"},
		{"nested null", `[[1, null]]`, "uint64[]"},
		{"number for bytes", `[5]`, "byte[]"},
		{"whole number past 2^53", `[2 ** 64]`, "uint128"},
		{"nested whole number past 2^53", `[[2 ** 64]]`, "uint128[]"},
		{"nested bad hex", `[[7, "hex:zz"]]`, "(uint64,byte[])"},
		{"nested null in a tuple", `[[7, null]]`, "(uint64,byte[])"},
		{"boolean for a string", `[true]`, "string"},
		{"number for a string", `[5]`, "string"},
		{"number for a nested string", `[[5, 1]]`, "(string,uint8)"},
		{"octal-looking text nested", `[["0100"]]`, "uint64[]"},
		{"lone surrogate in a string", `["\ud800"]`, "string"},
	}
	for _, tc := range cases {
		if encoded, err := abiArgsFromJS(t, tc.script, tc.typeName); err == nil {
			t.Errorf("%s: encoded %x, want refused", tc.name, encoded)
		}
	}
	for _, value := range []float64{math.NaN(), math.Inf(1)} {
		if text, err := abiArgText(value, "uint64"); err == nil {
			t.Errorf("abiArgText(%v) = %q, want refused", value, text)
		}
	}
	if text, err := abiArgText(big.NewInt(7), "uint64"); err != nil || text != "7" {
		t.Errorf("abiArgText(big 7) = %q, %v", text, err)
	}
}

// runJSAmount evaluates a JavaScript expression through toUint64, the way an
// amount, fee or ID argument is read.
func runJSAmount(t *testing.T, expr string) (value uint64, err error) {
	t.Helper()
	vm := goja.New()
	v, runErr := vm.RunString(expr)
	if runErr != nil {
		t.Fatalf("run %s: %v", expr, runErr)
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	return toUint64(vm, v), nil
}

func TestJSNumbersAreNeverCoerced(t *testing.T) {
	accepted := map[string]uint64{
		`5`:                      5,
		`0`:                      0,
		`"100"`:                  100,
		`"18446744073709551615"`: 18446744073709551615,
		`18446744073709551615n`:  18446744073709551615,
		`9007199254740991`:       9007199254740991,
	}
	for expr, want := range accepted {
		if got, err := runJSAmount(t, expr); err != nil || got != want {
			t.Errorf("%s = %d, %v; want %d", expr, got, err, want)
		}
	}
	// What JavaScript would turn into a number without saying so.
	for _, expr := range []string{
		`null`, `undefined`, `""`, `true`, `false`, `"0x10"`, `"1e6"`, `"0100"`, `"+5"`, `" 5"`,
		`"abc"`, `({})`, `[]`, `[5]`, `-1`, `1.5`, `-1n`, `2 ** 64`, `9007199254740993`, `18446744073709551616n`,
	} {
		if got, err := runJSAmount(t, expr); err == nil {
			t.Errorf("%s = %d, want refused", expr, got)
		}
	}
}

func TestJSNameArgumentsRefuseUndefinedAndNull(t *testing.T) {
	api := &API{runtime: goja.New()}
	read := func(expr string) (text string, err error) {
		v, runErr := api.runtime.RunString(expr)
		if runErr != nil {
			t.Fatalf("run %s: %v", expr, runErr)
		}
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("%v", r)
			}
		}()
		return api.stringArg(goja.FunctionCall{Arguments: []goja.Value{v}}, 0), nil
	}
	for expr, want := range map[string]string{`"alice"`: "alice", `31566704`: "31566704", `""`: ""} {
		if got, err := read(expr); err != nil || got != want {
			t.Errorf("%s = %q, %v; want %q", expr, got, err, want)
		}
	}
	// JavaScript would hand these over as the words "undefined" and "null",
	// which would then be looked up as an alias.
	for _, expr := range []string{`undefined`, `null`, `({})`, `[]`, `true`} {
		if got, err := read(expr); err == nil {
			t.Errorf("%s = %q, want refused", expr, got)
		}
	}
}

// A value inside an options object or an entry object takes the same forms
// as a top-level argument, so a value past 2^53 can be passed there too.
func TestJSNumbersInOptionsTakeBigIntAndDecimalStrings(t *testing.T) {
	vm := goja.New()
	read := func(expr string) (uint64, error) {
		v, err := vm.RunString(expr)
		if err != nil {
			t.Fatalf("run %s: %v", expr, err)
		}
		return toUint64Interface(v.Export())
	}
	for expr, want := range map[string]uint64{
		`5`: 5, `"1000000000000000000"`: 1000000000000000000, `1000000000000000000n`: 1000000000000000000,
	} {
		if got, err := read(expr); err != nil || got != want {
			t.Errorf("%s = %d, %v; want %d", expr, got, err, want)
		}
	}
	for _, expr := range []string{`1e18`, `null`, `true`, `""`, `"0x10"`, `"0100"`, `-1n`, `({})`} {
		if got, err := read(expr); err == nil {
			t.Errorf("%s = %d, want refused", expr, got)
		}
	}
}

func TestJSOptionsOfTheWrongTypeAreRefused(t *testing.T) {
	api := &API{runtime: goja.New()}
	try := func(read func()) (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("%v", r)
			}
		}()
		read()
		return nil
	}
	options := map[string]interface{}{"wait": "false", "note": int64(123), "absent": nil}
	if err := try(func() { api.optionBool(options, "wait", "send()") }); err == nil {
		t.Error(`{wait: "false"} is accepted; it would be read as not given, and wait`)
	}
	if err := try(func() { api.optionString(options, "note", "send()") }); err == nil {
		t.Error("{note: 123} is accepted; it would send no note")
	}
	// undefined and a missing key both mean "not given".
	for _, key := range []string{"absent", "missing"} {
		if err := try(func() {
			if _, present := api.optionBool(options, key, "send()"); present {
				t.Errorf("%s reads as given", key)
			}
		}); err != nil {
			t.Errorf("%s: %v", key, err)
		}
	}
}
