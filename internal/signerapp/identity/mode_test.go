// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package identity

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
)

func TestParseMode(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want Mode
	}{
		{name: "empty defaults signing", raw: "", want: ModeSigning},
		{name: "signing", raw: "signing", want: ModeSigning},
		{name: "attestation", raw: "attestation", want: ModeAttestation},
		{name: "dual", raw: "dual", want: ModeDual},
		{name: "trim lower", raw: " Attestation ", want: ModeAttestation},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseMode(tc.raw)
			if err != nil {
				t.Fatalf("ParseMode(%q) error = %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("ParseMode(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestParseModeRejectsUnknown(t *testing.T) {
	_, err := ParseMode("attestation-only")
	if err == nil {
		t.Fatal("ParseMode(unknown) error = nil")
	}
	if !strings.Contains(err.Error(), "must be one of") {
		t.Fatalf("ParseMode error = %q, want allowed values", err.Error())
	}
}

func TestStoredConfigApplyMode(t *testing.T) {
	effective, err := (&StoredConfig{}).Apply(ConfigDefaults{})
	if err != nil {
		t.Fatalf("Apply(default) error = %v", err)
	}
	if effective.Mode != ModeSigning {
		t.Fatalf("default Mode = %q, want %q", effective.Mode, ModeSigning)
	}

	effective, err = (&StoredConfig{Mode: "attestation"}).Apply(ConfigDefaults{})
	if err != nil {
		t.Fatalf("Apply(attestation) error = %v", err)
	}
	if effective.Mode != ModeAttestation {
		t.Fatalf("stored Mode = %q, want %q", effective.Mode, ModeAttestation)
	}

	if _, err := (&StoredConfig{Mode: "bad"}).Apply(ConfigDefaults{}); err == nil {
		t.Fatal("Apply(invalid mode) error = nil")
	}
}

func TestModeAllowsKeyType(t *testing.T) {
	if !ModeSigning.AllowsKeyType(keytypes.AttestedFalcon1024V1) {
		t.Fatal("signing mode rejected attested account key")
	}
	if ModeSigning.AllowsKeyType(keytypes.AttestorComponentEd25519V1) {
		t.Fatal("signing mode allowed attestor component key")
	}
	if !ModeAttestation.AllowsKeyType(keytypes.AttestorComponentEd25519V1) {
		t.Fatal("attestation mode rejected attestor component key")
	}
	if ModeAttestation.AllowsKeyType("ed25519") {
		t.Fatal("attestation mode allowed signing key")
	}
	if !ModeDual.AllowsKeyType("ed25519") || !ModeDual.AllowsKeyType(keytypes.AttestorComponentEd25519V1) {
		t.Fatal("dual mode did not allow both key classes")
	}
}

func TestValidateKeyTypesAllowedReportsConflicts(t *testing.T) {
	err := ValidateKeyTypesAllowed(ModeAttestation, map[string]string{
		"ADDR": "ed25519",
	})
	if err == nil {
		t.Fatal("ValidateKeyTypesAllowed() error = nil")
	}
	if !strings.Contains(err.Error(), `identity mode "attestation"`) || !strings.Contains(err.Error(), "ADDR:ed25519") {
		t.Fatalf("error = %q, want mode and conflicting key", err.Error())
	}
}
