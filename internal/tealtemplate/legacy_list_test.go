// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tealtemplate

import (
	"strings"
	"testing"
)

func TestExpandLists(t *testing.T) {
	params := map[string]string{
		"recipients": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ, BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBU5355I",
	}
	defs := []ParamDef{
		{Name: "recipients", Type: "address[]"},
	}

	got, err := ExpandLists("{{range @recipients}}addr {{.}}\n{{end}}", params, defs)
	if err != nil {
		t.Fatalf("ExpandLists() error = %v", err)
	}

	want := "addr AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ\naddr BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBU5355I\n"
	if got != want {
		t.Fatalf("ExpandLists() = %q, want %q", got, want)
	}
}

func TestExpandListsRejectsUnsupportedConstructs(t *testing.T) {
	params := map[string]string{"recipients": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"}
	defs := []ParamDef{{Name: "recipients", Type: "address[]"}}

	_, err := ExpandLists("{{len @recipients}}", params, defs)
	if err == nil {
		t.Fatal("ExpandLists() error = nil, want unsupported construct error")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("ExpandLists() error = %v, want unsupported construct error", err)
	}
}

func TestValidateListTemplatesRejectsUnsupportedConstructs(t *testing.T) {
	defs := []ParamDef{{Name: "recipients", Type: "address[]"}}
	err := ValidateListTemplates("{{len @recipients}}", defs)
	if err == nil {
		t.Fatal("ValidateListTemplates() error = nil, want unsupported construct error")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("ValidateListTemplates() error = %v, want unsupported construct error", err)
	}
}

func TestExpandListsRejectsNestedRanges(t *testing.T) {
	params := map[string]string{"recipients": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"}
	defs := []ParamDef{{Name: "recipients", Type: "address[]"}}

	_, err := ExpandLists("{{range @recipients}}{{range @recipients}}{{.}}{{end}}{{end}}", params, defs)
	if err == nil {
		t.Fatal("ExpandLists() error = nil, want nested range error")
	}
	if !strings.Contains(err.Error(), "nested range") {
		t.Fatalf("ExpandLists() error = %v, want nested range error", err)
	}
}

func TestExpandListsRejectsInvalidAddressBytes(t *testing.T) {
	params := map[string]string{"recipients": "not-an-address"}
	defs := []ParamDef{{Name: "recipients", Type: "address_bytes[]"}}

	_, err := ExpandLists("{{range @recipients}}byte {{.}}\n{{end}}", params, defs)
	if err == nil {
		t.Fatal("ExpandLists() error = nil, want invalid address error")
	}
	if !strings.Contains(err.Error(), "invalid Algorand address") {
		t.Fatalf("ExpandLists() error = %v, want invalid address error", err)
	}
}

func TestExpandListsSkipsMissingOptionalList(t *testing.T) {
	defs := []ParamDef{
		{Name: "allowed_optin_assets", Type: "uint64[]"},
	}

	got, err := ExpandLists("start\n{{range @allowed_optin_assets}}int {{.}}\n{{end}}end\n", map[string]string{}, defs)
	if err != nil {
		t.Fatalf("ExpandLists() error = %v", err)
	}

	want := "start\nend\n"
	if got != want {
		t.Fatalf("ExpandLists() = %q, want %q", got, want)
	}
}

func TestSubstituteVariablesRejectsInvalidAddressBytes(t *testing.T) {
	_, err := SubstituteVariables("byte @recipient", map[string]string{"recipient": "not-an-address"}, []ParamDef{
		{Name: "recipient", Type: "address_bytes"},
	})
	if err == nil {
		t.Fatal("SubstituteVariables() error = nil, want invalid address error")
	}
	if !strings.Contains(err.Error(), "invalid Algorand address") {
		t.Fatalf("SubstituteVariables() error = %v, want invalid address error", err)
	}
}
