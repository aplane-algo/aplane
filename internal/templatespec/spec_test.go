// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templatespec

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/lsigresource"
)

func TestValidateBaseKeyType(t *testing.T) {
	tests := []struct {
		name        string
		templateTyp TemplateType
		baseKeyType string
		wantErr     string
	}{
		{
			name:        "generic without base",
			templateTyp: TemplateTypeGeneric,
		},
		{
			name:        "generic with base",
			templateTyp: TemplateTypeGeneric,
			baseKeyType: "aplane.falcon1024.v1",
			wantErr:     "base_key_type must not be set for generic templates",
		},
		{
			name:        "composed with base",
			templateTyp: TemplateTypeComposed,
			baseKeyType: "aplane.falcon1024.v1",
		},
		{
			name:        "composed without base",
			templateTyp: TemplateTypeComposed,
			wantErr:     "base_key_type is required for composed templates",
		},
		{
			name:        "unknown template type",
			templateTyp: "custom",
			wantErr:     `unsupported template_type "custom"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBaseKeyType(tt.templateTyp, tt.baseKeyType)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateBaseKeyType() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidateBaseKeyType() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestActiveTemplateTypes(t *testing.T) {
	got := ActiveTemplateTypes()
	want := []TemplateType{TemplateTypeGeneric, TemplateTypeComposed}
	if len(got) != len(want) {
		t.Fatalf("ActiveTemplateTypes() len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ActiveTemplateTypes()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestBaseTemplateSpec_KeyType(t *testing.T) {
	spec := BaseTemplateSpec{
		Publisher: "APlane",
		Family:    "My-Template",
		Version:   3,
	}

	expected := "aplane.my-template.v3"
	if spec.KeyType() != expected {
		t.Errorf("Expected %s, got %s", expected, spec.KeyType())
	}
}

func TestBaseTemplateSpec_ValidateBase(t *testing.T) {
	derivationVersion3 := DerivationVersionAlgodAutoSalt
	derivationVersion99 := 99
	tests := []struct {
		name    string
		spec    BaseTemplateSpec
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid spec",
			spec: BaseTemplateSpec{
				SchemaVersion: 1,
				Publisher:     "test",
				Family:        "test",
				Version:       1,
				DisplayName:   "Test",
			},
			wantErr: false,
		},
		{
			name: "supported derivation version 3",
			spec: BaseTemplateSpec{
				SchemaVersion:     1,
				DerivationVersion: &derivationVersion3,
				Publisher:         "test",
				Family:            "test",
				Version:           1,
				DisplayName:       "Test",
			},
			wantErr: false,
		},
		{
			name: "unsupported derivation version",
			spec: BaseTemplateSpec{
				SchemaVersion:     1,
				DerivationVersion: &derivationVersion99,
				Publisher:         "test",
				Family:            "test",
				Version:           1,
				DisplayName:       "Test",
			},
			wantErr: true,
			errMsg:  "derivation_version 99 is not supported",
		},
		{
			name: "opcode ceiling above group maximum",
			spec: BaseTemplateSpec{
				SchemaVersion: 1,
				Publisher:     "test",
				Family:        "test",
				Version:       1,
				DisplayName:   "Test",
				MaxOpcodeCost: testUint64Ptr(lsigresource.MaximumDeclaredOpcodeCost + 1),
			},
			wantErr: true,
			errMsg:  "max_opcode_cost",
		},
		{
			name: "missing family",
			spec: BaseTemplateSpec{
				SchemaVersion: 1,
				Publisher:     "test",
				Version:       1,
				DisplayName:   "Test",
			},
			wantErr: true,
			errMsg:  "family is required",
		},
		{
			name: "invalid version",
			spec: BaseTemplateSpec{
				SchemaVersion: 1,
				Publisher:     "test",
				Family:        "test",
				Version:       0,
				DisplayName:   "Test",
			},
			wantErr: true,
			errMsg:  "version must be >= 1",
		},
		{
			name: "missing display name",
			spec: BaseTemplateSpec{
				SchemaVersion: 1,
				Publisher:     "test",
				Family:        "test",
				Version:       1,
			},
			wantErr: true,
			errMsg:  "display_name is required",
		},
		{
			name: "schema version too new",
			spec: BaseTemplateSpec{
				SchemaVersion: 99,
				Publisher:     "test",
				Family:        "test",
				Version:       1,
				DisplayName:   "Test",
			},
			wantErr: true,
			errMsg:  "schema_version 99 is newer than supported",
		},
		{
			name: "missing publisher",
			spec: BaseTemplateSpec{
				SchemaVersion: 1,
				Family:        "test",
				Version:       1,
				DisplayName:   "Test",
			},
			wantErr: true,
			errMsg:  "publisher is required",
		},
		{
			name: "unsafe publisher",
			spec: BaseTemplateSpec{
				SchemaVersion: 1,
				Publisher:     "../test",
				Family:        "test",
				Version:       1,
				DisplayName:   "Test",
			},
			wantErr: true,
			errMsg:  "publisher contains unsafe characters",
		},
		{
			name: "unsafe family",
			spec: BaseTemplateSpec{
				SchemaVersion: 1,
				Publisher:     "test",
				Family:        "bad..test",
				Version:       1,
				DisplayName:   "Test",
			},
			wantErr: true,
			errMsg:  "family contains unsafe characters",
		},
		{
			name: "family with single dot rejected",
			spec: BaseTemplateSpec{
				SchemaVersion: 1,
				Publisher:     "aplane",
				Family:        "white.list",
				Version:       1,
				DisplayName:   "Test",
			},
			wantErr: true,
			errMsg:  "family contains unsafe characters",
		},
		{
			name: "publisher with single dot rejected",
			spec: BaseTemplateSpec{
				SchemaVersion: 1,
				Publisher:     "ap.lane",
				Family:        "allowlist",
				Version:       1,
				DisplayName:   "Test",
			},
			wantErr: true,
			errMsg:  "publisher contains unsafe characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.spec.ValidateBase(1) // max schema version = 1
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestLogicSigOpcodeProfileDefaultsAndOverrides(t *testing.T) {
	t.Run("omitted uses one member", func(t *testing.T) {
		spec := BaseTemplateSpec{}
		if got := spec.LogicSigOpcodeProfile(false); got != lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling) {
			t.Fatalf("LogicSigOpcodeProfile() = %#v, want one-member default", got)
		}
	})

	t.Run("explicit override is preserved", func(t *testing.T) {
		value := uint64(45_000)
		spec := BaseTemplateSpec{MaxOpcodeCost: &value}
		if got := spec.LogicSigOpcodeProfile(false); got != lsigresource.DefaultOpcodeProfile(value) {
			t.Fatalf("LogicSigOpcodeProfile() = %#v, want absolute override %d", got, value)
		}
	})

	t.Run("bounded omission applies to every path", func(t *testing.T) {
		spec := BaseTemplateSpec{}
		want := lsigresource.BoundedOpcodeProfile(
			lsigresource.SingleTransactionOpcodeCeiling,
			lsigresource.SingleTransactionOpcodeCeiling,
			lsigresource.SingleTransactionOpcodeCeiling,
		)
		if got := spec.LogicSigOpcodeProfile(true); got != want {
			t.Fatalf("LogicSigOpcodeProfile() = %#v, want %#v", got, want)
		}
	})
}

func testUint64Ptr(value uint64) *uint64 {
	return &value
}
