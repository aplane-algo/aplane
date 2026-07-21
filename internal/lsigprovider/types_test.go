// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigprovider

import (
	"strings"
	"testing"
)

func TestNormalizeCreationParamsSortsListsByDefault(t *testing.T) {
	params := map[string]string{
		"recipients": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBU5355I, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
	}
	defs := []ParameterDef{{
		Name: "recipients",
		Type: "address[]",
	}}

	got, err := NormalizeCreationParams(params, defs)
	if err != nil {
		t.Fatalf("NormalizeCreationParams() error = %v", err)
	}

	want := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ,BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBU5355I"
	if got["recipients"] != want {
		t.Fatalf("recipients = %q, want %q", got["recipients"], want)
	}
	if params["recipients"] == got["recipients"] {
		t.Fatal("NormalizeCreationParams mutated or failed to copy the original params map")
	}
}

func TestNormalizeCreationParamsTrimsAddressListItems(t *testing.T) {
	params := map[string]string{
		"recipients": " BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBU5355I , AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ ",
	}
	defs := []ParameterDef{{
		Name: "recipients",
		Type: "address[]",
	}}

	got, err := NormalizeCreationParams(params, defs)
	if err != nil {
		t.Fatalf("NormalizeCreationParams() error = %v", err)
	}

	want := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ,BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBU5355I"
	if got["recipients"] != want {
		t.Fatalf("recipients = %q, want %q", got["recipients"], want)
	}
}

func TestNormalizeCreationParamsRejectsEmptyAddressListItems(t *testing.T) {
	params := map[string]string{
		"recipients": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ,",
	}
	defs := []ParameterDef{{
		Name: "recipients",
		Type: "address[]",
	}}

	_, err := NormalizeCreationParams(params, defs)
	if err == nil {
		t.Fatal("NormalizeCreationParams() error = nil, want empty item error")
	}
	if !strings.Contains(err.Error(), "invalid recipients: list contains an empty item") {
		t.Fatalf("NormalizeCreationParams() error = %v, want empty item error", err)
	}
}

func TestNormalizeCreationParamsLeavesOtherListTypesAlone(t *testing.T) {
	params := map[string]string{
		"labels": "beta, alpha",
	}
	defs := []ParameterDef{{
		Name: "labels",
		Type: "string[]",
	}}

	got, err := NormalizeCreationParams(params, defs)
	if err != nil {
		t.Fatalf("NormalizeCreationParams() error = %v", err)
	}
	if got["labels"] != params["labels"] {
		t.Fatalf("labels = %q, want unchanged %q", got["labels"], params["labels"])
	}
}

func TestNormalizeCreationParamsSortsUint64ListsByDefault(t *testing.T) {
	params := map[string]string{
		"allowed_optin_assets": "31566704, 10458941, 2",
	}
	defs := []ParameterDef{{
		Name: "allowed_optin_assets",
		Type: "uint64[]",
	}}

	got, err := NormalizeCreationParams(params, defs)
	if err != nil {
		t.Fatalf("NormalizeCreationParams() error = %v", err)
	}

	want := "2,10458941,31566704"
	if got["allowed_optin_assets"] != want {
		t.Fatalf("allowed_optin_assets = %q, want %q", got["allowed_optin_assets"], want)
	}
	if params["allowed_optin_assets"] == got["allowed_optin_assets"] {
		t.Fatal("NormalizeCreationParams mutated or failed to copy the original params map")
	}
}

func TestNormalizeCreationParamsRejectsInvalidUint64ListItems(t *testing.T) {
	params := map[string]string{
		"allowed_optin_assets": "10458941, nope",
	}
	defs := []ParameterDef{{
		Name: "allowed_optin_assets",
		Type: "uint64[]",
	}}

	_, err := NormalizeCreationParams(params, defs)
	if err == nil {
		t.Fatal("NormalizeCreationParams() error = nil, want invalid uint64 item error")
	}
	if !strings.Contains(err.Error(), `invalid allowed_optin_assets: list item "nope" is not a valid uint64`) {
		t.Fatalf("NormalizeCreationParams() error = %v, want invalid uint64 item error", err)
	}
}

func TestValidateAndOrderArgsRejectsLeftShift(t *testing.T) {
	argDefs := []RuntimeArgDef{
		{Name: "a", Required: false},
		{Name: "b", Required: true},
	}

	// Omitting non-trailing optional "a" while providing "b" would left-shift
	// "b" into slot 0; this must be rejected.
	_, err := ValidateAndOrderArgs(argDefs, map[string][]byte{"b": []byte("vb")})
	if err == nil {
		t.Fatal("expected rejection for omitted non-trailing optional, got nil")
	}

	// Providing both is fine (in order).
	args, err := ValidateAndOrderArgs(argDefs, map[string][]byte{"a": []byte("va"), "b": []byte("vb")})
	if err != nil {
		t.Fatalf("both provided: unexpected error %v", err)
	}
	if len(args) != 2 || string(args[0]) != "va" || string(args[1]) != "vb" {
		t.Fatalf("args = %v, want [va vb]", args)
	}

	// Omitting a trailing optional is fine.
	trailing := []RuntimeArgDef{{Name: "b", Required: true}, {Name: "a", Required: false}}
	args, err = ValidateAndOrderArgs(trailing, map[string][]byte{"b": []byte("vb")})
	if err != nil {
		t.Fatalf("trailing optional omitted: unexpected error %v", err)
	}
	if len(args) != 1 || string(args[0]) != "vb" {
		t.Fatalf("args = %v, want [vb]", args)
	}
}

func TestNormalizeCreationParamsCanonicalizesBytesHex(t *testing.T) {
	defs := []ParameterDef{{
		Name: "bounded_admin_public_key",
		Type: "bytes",
	}}

	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{"prefixed uppercase", "0xAB12CD", "ab12cd"},
		{"uppercase prefix", "0XAB12CD", "ab12cd"},
		{"uppercase", "AB12CD", "ab12cd"},
		{"surrounding whitespace", " ab12cd ", "ab12cd"},
		{"already canonical", "ab12cd", "ab12cd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeCreationParams(map[string]string{"bounded_admin_public_key": tc.input}, defs)
			if err != nil {
				t.Fatalf("NormalizeCreationParams() error = %v", err)
			}
			if got["bounded_admin_public_key"] != tc.want {
				t.Fatalf("bounded_admin_public_key = %q, want %q", got["bounded_admin_public_key"], tc.want)
			}
		})
	}
}

func TestNormalizeCreationParamsRejectsInvalidBytesHex(t *testing.T) {
	defs := []ParameterDef{{Name: "k", Type: "bytes"}}

	for _, input := range []string{"0x", "zz", "abc"} {
		if _, err := NormalizeCreationParams(map[string]string{"k": input}, defs); err == nil {
			t.Fatalf("NormalizeCreationParams(%q) error = nil, want invalid hex error", input)
		}
	}
}

func TestNormalizeCreationParamsMaterializesCanonicalDefaults(t *testing.T) {
	defs := []ParameterDef{
		{Name: "limit", Type: "uint64", Default: "100"},
		{Name: "proof", Type: "bytes", Default: "0xAB12"},
		{Name: "rounds", Type: "uint64[]", Default: "10, 2"},
	}

	for _, tc := range []struct {
		name   string
		params map[string]string
	}{
		{name: "nil", params: nil},
		{name: "missing", params: map[string]string{}},
		{name: "empty", params: map[string]string{"limit": "", "proof": "", "rounds": ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeCreationParams(tc.params, defs)
			if err != nil {
				t.Fatalf("NormalizeCreationParams() error = %v", err)
			}
			if got["limit"] != "100" || got["proof"] != "ab12" || got["rounds"] != "2,10" {
				t.Fatalf("NormalizeCreationParams() = %#v, want canonical defaults", got)
			}
		})
	}

	params := map[string]string{"limit": "200"}
	got, err := NormalizeCreationParams(params, defs)
	if err != nil {
		t.Fatalf("NormalizeCreationParams(explicit) error = %v", err)
	}
	if got["limit"] != "200" {
		t.Fatalf("explicit limit = %q, want 200", got["limit"])
	}
	if params["proof"] != "" || params["rounds"] != "" {
		t.Fatal("NormalizeCreationParams mutated the caller's map")
	}
}

func TestNormalizeCreationParamsPreservesNilWithoutDefaults(t *testing.T) {
	got, err := NormalizeCreationParams(nil, []ParameterDef{{Name: "limit", Type: "uint64"}})
	if err != nil {
		t.Fatalf("NormalizeCreationParams() error = %v", err)
	}
	if got != nil {
		t.Fatalf("NormalizeCreationParams() = %#v, want nil", got)
	}

	got, err = NormalizeCreationParams(nil, []ParameterDef{{Name: "required_limit", Type: "uint64", Required: true, Default: "100"}})
	if err != nil {
		t.Fatalf("NormalizeCreationParams(required) error = %v", err)
	}
	if got != nil {
		t.Fatalf("NormalizeCreationParams(required) = %#v, want nil so validation rejects the missing value", got)
	}
}
