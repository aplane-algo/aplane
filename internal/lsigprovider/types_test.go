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
