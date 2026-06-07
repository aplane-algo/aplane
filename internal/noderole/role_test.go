// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package noderole

import (
	"errors"
	"strings"
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
		{name: "attestor", raw: "sentry", want: RoleSentry},
		{name: "trim lower", raw: " Sentry ", want: RoleSentry},
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

func TestMarshalDocument(t *testing.T) {
	data, err := MarshalDocument(Document{
		Role:      RoleSigner,
		CreatedAt: "2026-06-07T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("MarshalDocument() error = %v", err)
	}
	got, _, found := strings.Cut(string(data), "\n")
	if !found || got != "schema_version: 1" {
		t.Fatalf("first yaml line = %q, want schema_version", got)
	}
	doc, err := ParseDocument(data)
	if err != nil {
		t.Fatalf("ParseDocument(marshaled) error = %v", err)
	}
	if doc.Role != RoleSigner {
		t.Fatalf("Role = %q, want %q", doc.Role, RoleSigner)
	}
}

func TestNewDocumentUsesRFC3339UTC(t *testing.T) {
	doc, err := NewDocument(RoleSentry, time.Date(2026, 6, 7, 12, 30, 0, 0, time.FixedZone("T", 3600)))
	if err != nil {
		t.Fatalf("NewDocument() error = %v", err)
	}
	if doc.CreatedAt != "2026-06-07T11:30:00Z" {
		t.Fatalf("CreatedAt = %q, want UTC RFC3339", doc.CreatedAt)
	}
}
