// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package appspec

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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
