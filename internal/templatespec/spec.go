// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package templatespec is a key-type template's specification: the fields
// every template type shares, their validation, and the template types. It
// knows no store, so the LogicSig template packages, which clients link, can
// read and check a template without the signer's store; templatestore keeps
// the encrypted file format and its storage.
package templatespec

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/keytypefmt"
	"github.com/aplane-algo/aplane/internal/lsigresource"
)

// BaseTemplateSpec contains fields common to all template types.
// Specific template systems embed this and add their own fields.
type BaseTemplateSpec struct {
	SchemaVersion     int  `yaml:"schema_version"`
	DerivationVersion *int `yaml:"derivation_version"`

	TemplateType string `yaml:"template_type"` // "generic" or "composed" (optional, aids detection)
	BaseKeyType  string `yaml:"base_key_type"`
	Publisher    string `yaml:"publisher"`
	Family       string `yaml:"family"`
	Version      int    `yaml:"version"`
	DisplayName  string `yaml:"display_name"`
	Description  string `yaml:"description"`
	DisplayColor string `yaml:"display_color"`
	// MaxOpcodeCost optionally declares an absolute reviewed worst-case cost of
	// every reachable path in the final compiler-returned program. Omission uses
	// SingleTransactionOpcodeCeiling, the one-member opcode unit shared by every
	// consensus profile APlane currently supports. A pointer preserves the
	// distinction between omission and an invalid explicit zero while parsing.
	MaxOpcodeCost *uint64 `yaml:"max_opcode_cost,omitempty"`
	// ValidRekeyTarget is the template's valid_rekey_target: the author's
	// declaration that an aplane key of this type may be the signing authority
	// an account is rekeyed to, its own account included, subject to its
	// program. Install requires it (ValidateRekeyTargetDeclaration); a pointer
	// is what lets that check see it is there. Each aplane key records it when
	// the key is created.
	ValidRekeyTarget *bool `yaml:"valid_rekey_target,omitempty"`
}

// ValidateRekeyTargetDeclaration is the install check for
// valid_rekey_target: a template on its way into a store must declare it.
func (s *BaseTemplateSpec) ValidateRekeyTargetDeclaration() error {
	if s == nil || s.ValidRekeyTarget == nil {
		return fmt.Errorf("valid_rekey_target is required: declare true only if an aplane key of this type may be the signing authority an account is rekeyed to, its own account included, subject to its program; else false")
	}
	return nil
}

// DerivationVersionAlgodAutoSalt uses TEAL v13 assembler auto-salting. The
// compiler-returned bytecode is authoritative and is never patched by
// APlane. It is the only supported derivation contract.
const DerivationVersionAlgodAutoSalt = 3

// KeyType returns the computed key type using publisher.family.vN.
func (s *BaseTemplateSpec) KeyType() string {
	publisher := strings.ToLower(strings.TrimSpace(s.Publisher))
	family := strings.ToLower(strings.TrimSpace(s.Family))
	return fmt.Sprintf("%s.%s.v%d", publisher, family, s.Version)
}

// ValidateBase validates the common fields.
func (s *BaseTemplateSpec) ValidateBase(maxSchemaVersion int) error {
	if s.SchemaVersion > maxSchemaVersion {
		return fmt.Errorf("schema_version %d is newer than supported version %d", s.SchemaVersion, maxSchemaVersion)
	}
	if s.DerivationVersion != nil {
		switch *s.DerivationVersion {
		case DerivationVersionAlgodAutoSalt:
		default:
			return fmt.Errorf("derivation_version %d is not supported", *s.DerivationVersion)
		}
	}
	if s.Family == "" {
		return fmt.Errorf("family is required")
	}
	if s.Publisher == "" {
		return fmt.Errorf("publisher is required")
	}
	if !keytypefmt.ValidSegment(strings.ToLower(strings.TrimSpace(s.Publisher))) {
		return fmt.Errorf("publisher contains unsafe characters")
	}
	if !keytypefmt.ValidSegment(strings.ToLower(strings.TrimSpace(s.Family))) {
		return fmt.Errorf("family contains unsafe characters")
	}
	if s.Version < 1 {
		return fmt.Errorf("version must be >= 1")
	}
	if s.DisplayName == "" {
		return fmt.Errorf("display_name is required")
	}
	if s.MaxOpcodeCost != nil && *s.MaxOpcodeCost > lsigresource.MaximumDeclaredOpcodeCost {
		return fmt.Errorf("max_opcode_cost %d exceeds maximum %d", *s.MaxOpcodeCost, lsigresource.MaximumDeclaredOpcodeCost)
	}
	return nil
}

// ValidateOpcodeCostDeclaration accepts omission as the supported one-member
// default while rejecting an explicitly declared zero ceiling.
func (s *BaseTemplateSpec) ValidateOpcodeCostDeclaration() error {
	if s == nil {
		return fmt.Errorf("template specification is required")
	}
	if s.MaxOpcodeCost != nil && *s.MaxOpcodeCost == 0 {
		return fmt.Errorf("max_opcode_cost must be greater than zero when declared")
	}
	return nil
}

// LogicSigOpcodeProfile materializes the template's effective numeric ceiling.
// Omission resolves to the compiled one-member default and is persisted
// numerically with generated keys. Callers validate the template first.
func (s *BaseTemplateSpec) LogicSigOpcodeProfile(bounded bool) lsigresource.OpcodeProfile {
	if s == nil {
		return lsigresource.OpcodeProfile{}
	}
	maxCost := uint64(lsigresource.SingleTransactionOpcodeCeiling)
	if s.MaxOpcodeCost != nil {
		maxCost = *s.MaxOpcodeCost
	}
	if bounded {
		return lsigresource.HostOpcodeProfile(maxCost, maxCost, maxCost)
	}
	return lsigresource.DefaultOpcodeProfile(maxCost)
}

// TemplateType identifies the type of template.
type TemplateType string

const (
	// TemplateTypeGeneric is for generic LogicSig templates.
	TemplateTypeGeneric TemplateType = "generic"
	// TemplateTypeComposed is for DSA composition templates.
	TemplateTypeComposed TemplateType = "composed"
)

// ValidateBaseKeyType validates the relationship between template_type and
// base_key_type.
func ValidateBaseKeyType(templateType TemplateType, baseKeyType string) error {
	baseKeyType = strings.TrimSpace(baseKeyType)
	switch templateType {
	case "", TemplateTypeGeneric:
		if baseKeyType != "" {
			return fmt.Errorf("base_key_type must not be set for generic templates")
		}
	case TemplateTypeComposed:
		if baseKeyType == "" {
			return fmt.Errorf("base_key_type is required for composed templates")
		}
	default:
		return fmt.Errorf("unsupported template_type %q", templateType)
	}
	return nil
}

// ActiveTemplateTypes returns template types that are loaded from identity
// storage in the current schema.
func ActiveTemplateTypes() []TemplateType {
	return []TemplateType{TemplateTypeGeneric, TemplateTypeComposed}
}
