// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package noderole

import (
	"errors"
	"testing"
	"time"
)

func TestParseRole(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want Role
	}{
		{name: "signer", raw: "signer", want: RoleSigner},
		{name: "cosigner", raw: "cosigner", want: RoleCosigner},
		{name: "trim lower", raw: " Cosigner ", want: RoleCosigner},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRole(tc.raw)
			if err != nil {
				t.Fatalf("ParseRole(%q) error = %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("ParseRole(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestParseRoleRejectsUnknown(t *testing.T) {
	_, err := ParseRole("dual")
	if !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("ParseRole(dual) error = %v, want ErrInvalidRole", err)
	}
}

func TestParseDocumentRejectsUnknownFields(t *testing.T) {
	_, err := ParseDocument([]byte("schema_version: 1\nrole: signer\nextra: true\n"))
	if !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("ParseDocument() error = %v, want ErrInvalidDocument", err)
	}
}

func TestNewDocumentUsesRFC3339UTC(t *testing.T) {
	doc, err := NewDocument(RoleCosigner, time.Date(2026, 6, 7, 12, 30, 0, 0, time.FixedZone("T", 3600)))
	if err != nil {
		t.Fatalf("NewDocument() error = %v", err)
	}
	if doc.CreatedAt != "2026-06-07T11:30:00Z" {
		t.Fatalf("CreatedAt = %q, want UTC RFC3339", doc.CreatedAt)
	}
}
