// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

import (
	"encoding/hex"
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
