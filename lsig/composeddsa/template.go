// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/addressderive"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/templatepolicy"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

// CurrentTemplateSchemaVersion is the current composed YAML schema version.
const CurrentTemplateSchemaVersion = 2

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
	if spec.SchemaVersion < 2 {
		if spec.Bounded != nil {
			return fmt.Errorf("schema_version 1 does not support bounded")
		}
	} else {
		if spec.Bounded == nil {
			return fmt.Errorf("composed schema_version 2 requires bounded")
		}
		for _, parameter := range spec.Parameters {
			if parameter.Name == BoundedAdminPublicKeyParameter {
				return fmt.Errorf("parameter %q is framework-injected and cannot be declared by the author", BoundedAdminPublicKeyParameter)
			}
		}
		if _, err := boundedProfileFromTemplate(spec.Bounded); err != nil {
			return err
		}
		if len(spec.RuntimeArgs) != 0 {
			return fmt.Errorf("composed schema_version 2 runtime_args must be declared inside bounded")
		}
		if err := validateBoundedArguments(spec.Bounded, spec.Parameters); err != nil {
			return err
		}
	}
	if spec.Bounded == nil || spec.Bounded.Layer3 == nil {
		if strings.TrimSpace(spec.TEAL) == "" {
			return fmt.Errorf("teal is required for custom Layer-3 policy")
		}
		if err := generictemplate.ValidateRelocatableTEAL(spec.TEAL); err != nil {
			return fmt.Errorf("composed template suffix: %w", err)
		}
	} else if strings.TrimSpace(spec.TEAL) != "" {
		return fmt.Errorf("framework-owned bounded Layer-3 policy must not declare teal")
	}
	if err := generictemplate.ValidateParameterSpecs(spec.Parameters); err != nil {
		return err
	}
	if spec.SchemaVersion < 2 {
		if err := generictemplate.ValidateRuntimeArgSpecs(spec.RuntimeArgs); err != nil {
			return err
		}
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
	bounded, err := boundedProfileFromTemplate(spec.Bounded)
	if err != nil {
		return nil, err
	}
	layer3, err := layer3PolicyFromTemplate(spec.Bounded, generictemplate.ParameterSpecToParameterDefs(spec.Parameters), bounded)
	if err != nil {
		return nil, err
	}
	boundedRuntimeMetadata, runtimeDefs := boundedRuntimeArgsFromTemplate(spec.Bounded)
	return NewComposedDSA(Config{
		KeyType:            spec.KeyType(),
		BaseKeyType:        base.BaseKeyType,
		FamilyName:         base.FamilyName,
		Version:            spec.Version,
		DisplayName:        spec.DisplayName,
		Description:        spec.Description,
		Ops:                base.Ops,
		TEALSuffix:         strings.TrimSpace(spec.TEAL),
		SaltStyle:          mustTemplateSaltStyle(spec.DerivationVersion),
		TemplateMode:       generictemplate.EffectiveTemplateMode(spec),
		TemplateVars:       spec.TemplateVariables,
		Params:             generictemplate.ParameterSpecToParameterDefs(spec.Parameters),
		RuntimeArgs:        append(generictemplate.RuntimeArgSpecToRuntimeArgDefs(spec.RuntimeArgs), runtimeDefs...),
		BoundedRuntimeArgs: boundedRuntimeMetadata,
		DerivedArgs:        boundedDerivedArgsFromTemplate(spec.Bounded),
		Bounded:            bounded,
		Layer3:             layer3,
	}), nil
}

func validateBoundedArguments(spec *generictemplate.BoundedAuthorizationSpec, parameters []generictemplate.ParameterSpec) error {
	if spec == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(spec.RuntimeArgs)+len(spec.DerivedArgs))
	parameterTypes := make(map[string]string, len(parameters))
	for _, parameter := range parameters {
		parameterTypes[parameter.Name] = parameter.Type
	}
	rekeyUsesLayer3 := false
	for _, operation := range spec.AdminOperations {
		if operation.Kind == boundedmeta.AdminOperationRekey && operation.Authorization == boundedmeta.AdminAuthorizationSpend && operation.PolicyGate == boundedmeta.PolicyGateLayer3 {
			rekeyUsesLayer3 = true
		}
	}
	for _, arg := range spec.RuntimeArgs {
		if arg.Name == "" || (arg.Type != "bytes" && arg.Type != "string" && arg.Type != "uint64") {
			return fmt.Errorf("bounded.runtime_args contains invalid argument %q", arg.Name)
		}
		if arg.MaxSize <= 0 || arg.ByteLength < 0 || arg.ByteLength > arg.MaxSize {
			return fmt.Errorf("bounded.runtime_args argument %q has invalid size bounds", arg.Name)
		}
		if _, duplicate := seen[arg.Name]; duplicate {
			return fmt.Errorf("bounded argument name %q is duplicated", arg.Name)
		}
		seen[arg.Name] = struct{}{}
		requiredSpend, requiredRekey := false, false
		for _, path := range arg.RequiredOn {
			switch path {
			case boundedmeta.PathSpend:
				if requiredSpend {
					return fmt.Errorf("bounded.runtime_args argument %q duplicates required_on %q", arg.Name, path)
				}
				requiredSpend = true
			case "rekey":
				if requiredRekey {
					return fmt.Errorf("bounded.runtime_args argument %q duplicates required_on %q", arg.Name, path)
				}
				requiredRekey = true
			default:
				return fmt.Errorf("bounded.runtime_args argument %q has unsupported required_on path %q", arg.Name, path)
			}
		}
		if !requiredSpend {
			return fmt.Errorf("bounded.runtime_args argument %q must be required on spend", arg.Name)
		}
		if requiredRekey != rekeyUsesLayer3 {
			return fmt.Errorf("bounded.runtime_args argument %q rekey requirement does not match the Layer-3 policy gate", arg.Name)
		}
	}
	for _, arg := range spec.DerivedArgs {
		if arg.Name == "" || arg.Kind != boundedmeta.DerivedArgMerkleProof || arg.Parameter == "" || arg.MaxSize != boundedmeta.MerkleProofSize {
			return fmt.Errorf("bounded.derived_args contains invalid argument %q", arg.Name)
		}
		if _, duplicate := seen[arg.Name]; duplicate {
			return fmt.Errorf("bounded argument name %q is duplicated", arg.Name)
		}
		if parameterTypes[arg.Parameter] != "address[]" {
			return fmt.Errorf("bounded.derived_args argument %q requires address[] parameter %q", arg.Name, arg.Parameter)
		}
		seen[arg.Name] = struct{}{}
	}
	return nil
}

func boundedRuntimeArgsFromTemplate(spec *generictemplate.BoundedAuthorizationSpec) ([]boundedmeta.RuntimeArg, []lsigprovider.RuntimeArgDef) {
	if spec == nil {
		return nil, nil
	}
	metadata := make([]boundedmeta.RuntimeArg, len(spec.RuntimeArgs))
	defs := make([]lsigprovider.RuntimeArgDef, len(spec.RuntimeArgs))
	for i, arg := range spec.RuntimeArgs {
		metadata[i] = boundedmeta.RuntimeArg{
			Name: arg.Name, Label: arg.Label, Description: arg.Description, Type: arg.Type,
			Required: true, ByteLength: arg.ByteLength, MaxSize: arg.MaxSize,
		}
		defs[i] = lsigprovider.RuntimeArgDef{
			Name: arg.Name, Label: arg.Label, Description: arg.Description, Type: arg.Type,
			Required: true, ByteLength: arg.ByteLength, MaxSize: arg.MaxSize,
		}
	}
	return metadata, defs
}

func boundedDerivedArgsFromTemplate(spec *generictemplate.BoundedAuthorizationSpec) []boundedmeta.DerivedArg {
	if spec == nil {
		return nil
	}
	args := make([]boundedmeta.DerivedArg, len(spec.DerivedArgs))
	for i, arg := range spec.DerivedArgs {
		args[i] = boundedmeta.DerivedArg{Name: arg.Name, Kind: arg.Kind, Parameter: arg.Parameter, MaxSize: arg.MaxSize}
	}
	return args
}

func boundedProfileFromTemplate(spec *generictemplate.BoundedAuthorizationSpec) (*BoundedAuthorizationProfile, error) {
	if spec == nil {
		return nil, nil
	}
	if spec.MaxFee == nil {
		return nil, fmt.Errorf("bounded.max_fee is required")
	}
	profile := &BoundedAuthorizationProfile{
		Contract: spec.Contract,
		MaxFee:   *spec.MaxFee,
	}
	for _, effect := range spec.SpendEffects {
		switch effect {
		case string(txeffects.SpendEffectPay):
			profile.SpendEffects = append(profile.SpendEffects, txeffects.SpendEffectPay)
		case string(txeffects.SpendEffectAxfer):
			profile.SpendEffects = append(profile.SpendEffects, txeffects.SpendEffectAxfer)
		case string(txeffects.SpendEffectAssetOptIn):
			profile.SpendEffects = append(profile.SpendEffects, txeffects.SpendEffectAssetOptIn)
		default:
			return nil, fmt.Errorf("bounded.spend_effects contains unsupported effect %q", effect)
		}
	}
	for _, operation := range spec.AdminOperations {
		profile.AdminOperations = append(profile.AdminOperations, AdminOperationSpec{
			Kind:          AdminOperationKind(operation.Kind),
			Authorization: AdminOperationAuthorization(operation.Authorization),
			PolicyGate:    AdminPolicyGate(operation.PolicyGate),
		})
	}
	canonical, err := canonicalBoundedProfile(profile)
	if err != nil {
		return nil, fmt.Errorf("invalid bounded profile: %w", err)
	}
	return canonical, nil
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
