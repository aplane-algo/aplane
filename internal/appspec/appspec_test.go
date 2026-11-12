// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package appspec

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	abi "github.com/algorand/avm-abi/abi"
)

func testABIPath(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "test", "fixtures", "testapp", "aplane_test.json")
}

func TestLoadAndResolveMethod(t *testing.T) {
	spec, err := Load(testABIPath(t))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	method, err := spec.ResolveMethod("increment")
	if err != nil {
		t.Fatalf("ResolveMethod() error = %v", err)
	}

	if got := method.Signature(); got != "increment(uint64)void" {
		t.Fatalf("Signature() = %q, want increment(uint64)void", got)
	}
	if got := hex.EncodeToString(method.Selector()); got != "8296da2e" {
		t.Fatalf("Selector() = %q, want 8296da2e", got)
	}
}

func TestResolveMethodOverloadError(t *testing.T) {
	spec := &Contract{
		Methods: []Method{
			{Name: "x", Args: []MethodArg{{Type: "uint64"}}, Returns: MethodReturn{Type: "void"}},
			{Name: "x", Args: []MethodArg{{Type: "string"}}, Returns: MethodReturn{Type: "void"}},
		},
	}

	if _, err := spec.ResolveMethod("x"); err == nil {
		t.Fatal("ResolveMethod() error = nil, want overload error")
	}
}

func TestEncodeArgs(t *testing.T) {
	spec, err := Load(testABIPath(t))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	increment, err := spec.ResolveMethod("increment")
	if err != nil {
		t.Fatalf("ResolveMethod() error = %v", err)
	}
	encoded, err := increment.EncodeArgs([]string{"11"})
	if err != nil {
		t.Fatalf("EncodeArgs() error = %v", err)
	}
	if got := hex.EncodeToString(encoded[0]); got != "8296da2e" {
		t.Fatalf("selector = %s, want 8296da2e", got)
	}
	if got := hex.EncodeToString(encoded[1]); got != "000000000000000b" {
		t.Fatalf("uint64 arg = %s, want 000000000000000b", got)
	}

	setBox, err := spec.ResolveMethod("set_box")
	if err != nil {
		t.Fatalf("ResolveMethod() error = %v", err)
	}
	encoded, err = setBox.EncodeArgs([]string{"text:config", "hex:0102"})
	if err != nil {
		t.Fatalf("EncodeArgs() error = %v", err)
	}
	if got := hex.EncodeToString(encoded[0]); got != "6eb66b06" {
		t.Fatalf("selector = %s, want 6eb66b06", got)
	}
	if got := hex.EncodeToString(encoded[1]); got != "0006636f6e666967" {
		t.Fatalf("first bytes arg = %s, want 0006636f6e666967", got)
	}
	if got := hex.EncodeToString(encoded[2]); got != "00020102" {
		t.Fatalf("second bytes arg = %s, want 00020102", got)
	}
}

func TestParseArgValueAddressAndTuple(t *testing.T) {
	addressValue, err := parseArgValue("address", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")
	if err != nil {
		t.Fatalf("parseArgValue(address) error = %v", err)
	}
	addressBytes, ok := addressValue.([]byte)
	if !ok || len(addressBytes) != 32 {
		t.Fatalf("address parse returned %T len=%d, want []byte len=32", addressValue, len(addressBytes))
	}

	tupleValue, err := parseArgValue("(uint64,bool)", "json:[7,true]")
	if err != nil {
		t.Fatalf("parseArgValue(tuple) error = %v", err)
	}
	tupleSlice, ok := tupleValue.([]interface{})
	if !ok || len(tupleSlice) != 2 {
		t.Fatalf("tuple parse returned %T len=%d, want []interface{} len=2", tupleValue, len(tupleSlice))
	}
}

func TestValidateABITypeRejectsOversizedStaticByteArray(t *testing.T) {
	err := validateABIType("byte[999999999999999999999]")
	if err == nil || err.Error() != `invalid static byte array type "byte[999999999999999999999]": size must be between 0 and 65535` {
		t.Fatalf("validateABIType() error = %v", err)
	}
}

func TestLoadRejectsOversizedStaticByteArray(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	data, err := json.Marshal(Contract{
		Name: "bad",
		Methods: []Method{{
			Name:    "set_box",
			Args:    []MethodArg{{Name: "v", Type: "byte[999999999999999999999]"}},
			Returns: MethodReturn{Type: "void"},
		}},
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err = Load(path)
	if err == nil || err.Error() != `invalid static byte array type "byte[999999999999999999999]": size must be between 0 and 65535` {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestParseArgValueHoldsScalarsToPlainDecimal(t *testing.T) {
	accepted := []struct{ typeName, raw string }{
		{"uint64", "0"},
		{"uint64", "100"},
		{"uint64", "json:100"},
		{"byte", "7"},
		{"ufixed64x2", "1.25"},
		{"ufixed64x2", "3"},
		{"bool", "true"},
		{"bool", "false"},
		{"uint64[]", "[1,2,3]"},
		{"(uint64,bool)", "[1,true]"},
	}
	for _, tc := range accepted {
		if _, err := parseArgValue(tc.typeName, tc.raw); err != nil {
			t.Errorf("parseArgValue(%s, %q) = %v, want accepted", tc.typeName, tc.raw, err)
		}
	}

	refused := []struct{ typeName, raw string }{
		{"uint64", "0100"},
		{"uint64", "0x10"},
		{"uint64", "0b11"},
		{"uint64", "1_000"},
		{"uint64", "+5"},
		{"uint64", "null"},
		{"uint64", ""},
		{"uint64", " 5"},
		{"byte", "010"},
		{"byte", "null"},
		{"ufixed64x2", "010/1"},
		{"ufixed64x2", "null"},
		{"ufixed64x2", "1e2"},
		{"bool", "null"},
		{"bool", "1"},
		{"bool", "TRUE"},
		{"uint64[]", "[1,null]"},
		{"(uint64,bool)", "[1,null]"},
		{"(uint64,(bool,uint8))", "[1,[null,2]]"},
		{"string", "json:[104,null,105]"},
		{"string", "json:null"},
	}
	for _, tc := range refused {
		if value, err := parseArgValue(tc.typeName, tc.raw); err == nil {
			t.Errorf("parseArgValue(%s, %q) = %v, want refused", tc.typeName, tc.raw, value)
		}
	}
}

// encodeOneArg encodes raw as the only argument of a method that takes typeName
// and returns the argument's bytes, without the selector.
func encodeOneArg(typeName, raw string) ([]byte, error) {
	method := Method{Name: "m", Args: []MethodArg{{Name: "a", Type: typeName}}, Returns: MethodReturn{Type: "void"}}
	encoded, err := method.EncodeArgs([]string{raw})
	if err != nil {
		return nil, err
	}
	return encoded[1], nil
}

func TestNestedByteValuesNameTheirEncoding(t *testing.T) {
	const zeroAddress = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	test := "0000000000000064000a000474657374" // (100, "test")
	accepted := []struct{ typeName, raw, wantHex string }{
		{"(uint64,byte[])", `json:[100,"text:test"]`, test},
		{"(uint64,byte[])", `json:[100,"str:test"]`, test},
		{"(uint64,byte[])", `json:[100,"b64:dGVzdA=="]`, test},
		{"(uint64,byte[])", `json:[100,"hex:74657374"]`, test},
		{"(uint64,byte[])", `[100,"0x74657374"]`, test},
		{"(uint64,byte[])", `[100,[116,101,115,116]]`, test},
		{"(uint64,byte[])", `[100,"text:"]`, "0000000000000064000a0000"},
		{"(byte[4],uint8)", `json:["text:test",1]`, "7465737401"},
		{"(byte[4],uint8)", `json:[[116,101,115,116],1]`, "7465737401"},
		{"(byte[8],bool)", `json:["int:5",true]`, "000000000000000580"},
		{"(byte[32],uint8)", `json:["addr:` + zeroAddress + `",7]`, strings.Repeat("00", 32) + "07"},
		{"byte[][]", `json:["text:ab","hex:0102"]`, "0002000400080002616200020102"},
		{"byte[][]", `json:[[97,98],[1,2]]`, "0002000400080002616200020102"},
		{"byte[2][]", `json:["text:ab"]`, "00016162"},
		{"(uint64,(bool,byte[]))", `json:[1,[true,"text:test"]]`, "0000000000000001000a800003000474657374"},
		{"(uint64,byte[])[]", `json:[[1,"text:a"]]`, "000100020000000000000001000a000161"},
		// Strings that are not byte arrays are read as they always were.
		{"(uint64,string)", `json:[1,"dGVzdA=="]`, "0000000000000001000a00086447567a64413d3d"},
		{"(uint64,string)", `json:[1,"text:x"]`, "0000000000000001000a0006746578743a78"},
		{"(uint64,address)", `json:[1,"` + zeroAddress + `"]`, "0000000000000001" + strings.Repeat("00", 32)},
		// Numbers keep their text: 2^53+1 would round to 2^53 as a float.
		{"(uint64,byte[])", `json:[9007199254740993,"text:a"]`, "0020000000000001000a000161"},
		{"(uint64,byte[])", `json:[18446744073709551615,"text:a"]`, "ffffffffffffffff000a000161"},
		// Text that is not ASCII is sent as its UTF-8, written or escaped.
		{"(uint64,byte[])", `json:[100,"text:héllo"]`, "0000000000000064000a000668c3a96c6c6f"},
		{"(uint64,byte[])", `json:[100,"text:é"]`, "0000000000000064000a0002c3a9"},
		{"(uint64,byte[])", `json:[100,"text:😀"]`, "0000000000000064000a0004f09f9880"},
		// JSON ignores the whitespace around a value.
		{"(uint64,byte[])", " [100,\"text:a\"]\n", "0000000000000064000a000161"},
		{"(uint64,bool)", `json: [1,true] `, "000000000000000180"},
		// A top-level byte array still reads bare text as text, and has no
		// number-list form.
		{"byte[]", "test", "000474657374"},
		{"byte[]", "[104,105]", "00095b3130342c3130355d"},
	}
	for _, tc := range accepted {
		got, err := encodeOneArg(tc.typeName, tc.raw)
		if err != nil {
			t.Errorf("%s %s: %v", tc.typeName, tc.raw, err)
			continue
		}
		if hex.EncodeToString(got) != tc.wantHex {
			t.Errorf("%s %s = %x, want %s", tc.typeName, tc.raw, got, tc.wantHex)
		}
	}

	refused := []struct{ typeName, raw, wantErr string }{
		{"(uint64,byte[])", `json:[100,"test"]`,
			`element 1: nested byte value "test" needs an encoding prefix: hex:, b64:, text:, str:, int:, addr:, 0x`},
		{"(uint64,byte[])", `[100,"dGVzdA=="]`, `nested byte value "dGVzdA==" needs an encoding prefix`},
		{"(uint64,byte[])", `[100,""]`, `nested byte value "" needs an encoding prefix`},
		{"(uint64,byte[])", `[100,"key:value"]`, `nested byte value "key:value" needs an encoding prefix`},
		{"(uint64,byte[])", `[100,"hex:zz"]`, `nested byte value "hex:zz": invalid hex value`},
		{"byte[][]", `json:["text:a","b"]`, `element 1: nested byte value "b" needs an encoding prefix`},
		{"(uint64,(bool,byte[]))", `json:[1,[true,"test"]]`, `element 1: element 1: nested byte value "test"`},
		{"(byte[4],uint8)", `json:["text:abc",1]`, `nested byte value "text:abc" is 3 bytes; byte[4] takes 4`},
		{"(byte[4],uint8)", `json:["test",1]`, `nested byte value "test" needs an encoding prefix`},
		{"(byte[4],uint8)", `json:[[1,2,3],1]`, ""},
		{"(uint64,uint8[])", `json:[1,"text:a"]`, ""},
		{"(uint64,bool)", `json:[1,true] [2]`, "more after the value"},
		{"(uint64,bool)", `json:[1,true]]`, ""},
		{"(uint64,bool)", `[1,true],`, ""},
		// The JSON reader would send each of these as the bytes ef bf bd.
		{"(uint64,byte[])", `json:[100,"text:\ud800"]`, "holds the replacement character U+FFFD"},
		{"(uint64,byte[])", "json:[100,\"text:\xff\"]", "write the bytes with a hex: or b64: prefix"},
		{"(uint64,byte[])", `json:[100,"str:a�"]`, "holds the replacement character U+FFFD"},
	}
	for _, tc := range refused {
		got, err := encodeOneArg(tc.typeName, tc.raw)
		if err == nil {
			t.Errorf("%s %s = %x, want refused", tc.typeName, tc.raw, got)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s %s: %v, want %q", tc.typeName, tc.raw, err, tc.wantErr)
		}
	}
}

func TestParseArgValueReadsDecimalAsTyped(t *testing.T) {
	abiType, err := abi.TypeOf("uint64")
	if err != nil {
		t.Fatal(err)
	}
	value, err := parseArgValue("uint64", "100")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := abiType.Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint64(encoded); got != 100 {
		t.Fatalf("uint64 100 encoded as %d", got)
	}
}
