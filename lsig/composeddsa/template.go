// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/addressderive"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/templatepolicy"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

// CurrentTemplateSchemaVersion is the current composed YAML schema version.
const CurrentTemplateSchemaVersion = 1

// TemplateSpec represents the YAML schema for a composed DSA template. The
// schema is identical to the generic template schema; composed-specific rules
// (template_type, base_key_type, suffix-fragment TEAL) live in
// ValidateTemplateSpec.
type TemplateSpec = generictemplate.TemplateSpec

// ParseTemplateSpec parses YAML data into a composed template spec.
func ParseTemplateSpec(data []byte) (*TemplateSpec, error) {
	return generictemplate.ParseTemplateSpec(data)
}

// ValidateTemplateSpec validates required fields and composed-base consistency.
func ValidateTemplateSpec(spec *TemplateSpec) error {
	if err := spec.ValidateBase(CurrentTemplateSchemaVersion); err != nil {
		return err
	}
	if templatestore.TemplateType(spec.TemplateType) != templatestore.TemplateTypeComposed {
		return fmt.Errorf("template_type must be %q for composed templates", templatestore.TemplateTypeComposed)
	}
	if err := templatestore.ValidateBaseKeyType(templatestore.TemplateType(spec.TemplateType), spec.BaseKeyType); err != nil {
		return err
	}
	if !IsBaseRegistered(spec.BaseKeyType) {
		return fmt.Errorf("base_key_type %q is not registered as composable", spec.BaseKeyType)
	}
	if strings.TrimSpace(spec.TEAL) == "" {
		return fmt.Errorf("teal is required")
	}
	if err := generictemplate.ValidateRelocatableTEAL(spec.TEAL); err != nil {
		return fmt.Errorf("composed template suffix: %w", err)
	}
	if err := generictemplate.ValidateParameterSpecs(spec.Parameters); err != nil {
		return err
	}
	if err := generictemplate.ValidateRuntimeArgSpecs(spec.RuntimeArgs); err != nil {
		return err
	}
	return generictemplate.ValidateTemplateSpecMode(spec)
}

// NewProviderFromTemplateSpec creates a composed provider from a parsed spec.
func NewProviderFromTemplateSpec(spec *TemplateSpec) (*ComposedDSA, error) {
	if err := ValidateTemplateSpec(spec); err != nil {
		return nil, err
	}
	base, ok := LookupBase(spec.BaseKeyType)
	if !ok {
		return nil, fmt.Errorf("base_key_type %q is not registered as composable", spec.BaseKeyType)
	}
	return NewComposedDSA(Config{
		KeyType:      spec.KeyType(),
		BaseKeyType:  base.BaseKeyType,
		FamilyName:   base.FamilyName,
		Version:      spec.Version,
		DisplayName:  spec.DisplayName,
		Description:  spec.Description,
		Ops:          base.Ops,
		TEALSuffix:   strings.TrimSpace(spec.TEAL),
		SaltStyle:    mustTemplateSaltStyle(spec.DerivationVersion),
		TemplateMode: generictemplate.EffectiveTemplateMode(spec),
		TemplateVars: spec.TemplateVariables,
		Params:       generictemplate.ParameterSpecToParameterDefs(spec.Parameters),
		RuntimeArgs:  generictemplate.RuntimeArgSpecToRuntimeArgDefs(spec.RuntimeArgs),
	}), nil
}

func mustTemplateSaltStyle(derivationVersion *int) lsigsalt.Style {
	if derivationVersion == nil {
		return lsigsalt.StyleNone
	}
	style, err := generictemplate.SaltStyleForDerivationVersion(*derivationVersion)
	if err != nil {
		panic("composeddsa: validated template derivation version rejected: " + err.Error())
	}
	return style
}

// SemanticFingerprint returns a stable semantic fingerprint for the
// compatibility-bearing portions of a composed YAML template.
func SemanticFingerprint(data []byte) (string, error) {
	spec, err := ParseTemplateSpec(data)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}
	provider, err := NewProviderFromTemplateSpec(spec)
	if err != nil {
		return "", fmt.Errorf("invalid template: %w", err)
	}
	return provider.CompatibilityFingerprint(), nil
}

// PrepareKeystoreTemplateRegistration parses and validates one decrypted
// composed template. The caller remains responsible for state-record policy and
// registry conflict handling before invoking Register.
func PrepareKeystoreTemplateRegistration(keyType string, data []byte) (templatepolicy.PreparedTemplateRegistration, error) {
	spec, err := ParseTemplateSpec(data)
	if err != nil {
		return templatepolicy.PreparedTemplateRegistration{}, err
	}
	provider, err := NewProviderFromTemplateSpec(spec)
	if err != nil {
		return templatepolicy.PreparedTemplateRegistration{}, err
	}
	if provider.KeyType() != keyType {
		return templatepolicy.PreparedTemplateRegistration{}, fmt.Errorf("template key type %q does not match state key type %q", provider.KeyType(), keyType)
	}
	base, ok := LookupBase(spec.BaseKeyType)
	if !ok {
		return templatepolicy.PreparedTemplateRegistration{}, fmt.Errorf("base_key_type %q is not registered as composable", spec.BaseKeyType)
	}
	return templatepolicy.PreparedTemplateRegistration{
		Fingerprint: provider.CompatibilityFingerprint(),
		Register: func() bool {
			addressderive.Register(keyType, base.NewAddressDeriver(keyType))
			return logicsigdsa.RegisterIfAbsent(provider)
		},
	}, nil
}
