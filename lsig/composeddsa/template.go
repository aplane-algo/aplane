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
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/rekeylist"
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

// ParseTemplateSpec parses YAML data into a composed template spec. A template
// can't declare the `none` Layer 3 policy: the plain hosts' bounds offer that
// account, selected by recipient_scope=any, and a second route would duplicate it.
func ParseTemplateSpec(data []byte) (*TemplateSpec, error) {
	spec, err := generictemplate.ParseTemplateSpec(data)
	if err != nil {
		return nil, err
	}
	if spec.Bounded != nil && spec.Bounded.Layer3 != nil && spec.Bounded.Layer3.Policy == Layer3PolicyNone {
		return nil, fmt.Errorf("bounded.layer3 policy %q is offered only by the plain hosts' bounds, with recipient_scope=any", Layer3PolicyNone)
	}
	return spec, nil
}

// templateBaseRules answers the questions a template asks about its base.
type templateBaseRules struct {
	registered     func(baseKeyType string) bool
	allowsCosigner func(baseKeyType string) bool
}

var productionTemplateBaseRules = templateBaseRules{
	registered:     IsBaseRegistered,
	allowsCosigner: boundedContractAllowsCosigner,
}

// boundedContractAllowsCosigner reports whether the generation support policy
// admits a cosigner on a bounded2 account over baseKeyType. The policy is the
// one record of which bases the cosigner workflow is reviewed for.
func boundedContractAllowsCosigner(baseKeyType string) bool {
	support, ok := productionBoundedGenerationPolicy(BoundedContract, baseKeyType)
	return ok && support.cosigner
}

// ValidateTemplateSpec validates required fields and composed-base consistency.
func ValidateTemplateSpec(spec *TemplateSpec) error {
	return validateTemplateSpec(spec, productionTemplateBaseRules)
}

func validateTemplateSpec(spec *TemplateSpec, rules templateBaseRules) error {
	if err := spec.ValidateBase(CurrentTemplateSchemaVersion); err != nil {
		return err
	}
	if templatestore.TemplateType(spec.TemplateType) != templatestore.TemplateTypeComposed {
		return fmt.Errorf("template_type must be %q for composed templates", templatestore.TemplateTypeComposed)
	}
	if err := templatestore.ValidateBaseKeyType(templatestore.TemplateType(spec.TemplateType), spec.BaseKeyType); err != nil {
		return err
	}
	if !rules.registered(spec.BaseKeyType) {
		return fmt.Errorf("base_key_type %q is not registered as composable", spec.BaseKeyType)
	}
	for _, parameter := range spec.Parameters {
		if isBoundedCosignerReservedName(parameter.Name) {
			return fmt.Errorf("parameter %q is framework-injected or reserved and cannot be declared by the author", parameter.Name)
		}
	}
	if spec.SchemaVersion < 2 {
		if spec.Bounded != nil {
			return fmt.Errorf("schema_version 1 does not support bounded")
		}
	} else {
		if spec.Bounded == nil {
			return fmt.Errorf("composed schema_version 2 requires bounded")
		}
		if _, err := boundedProfileFromTemplate(spec.Bounded); err != nil {
			return err
		}
		if spec.Bounded.Cosigner != nil && !rules.allowsCosigner(spec.BaseKeyType) {
			return fmt.Errorf("bounded.cosigner is not reviewed for base_key_type %q", spec.BaseKeyType)
		}
		if len(spec.RuntimeArgs) != 0 {
			return fmt.Errorf("composed schema_version 2 runtime_args must be declared inside bounded")
		}
		if err := validateBoundedArguments(spec.Bounded, spec.Parameters); err != nil {
			return err
		}
	}
	hasAuthorTEAL := strings.TrimSpace(spec.TEAL) != ""
	if !hasAuthorTEAL && (spec.Bounded == nil || spec.Bounded.Layer3 == nil) {
		return fmt.Errorf("teal is required for custom Layer-3 policy")
	}
	if hasAuthorTEAL {
		if err := generictemplate.ValidateRelocatableTEAL(spec.TEAL); err != nil {
			return fmt.Errorf("composed template suffix: %w", err)
		}
	}
	if err := generictemplate.ValidateParameterSpecs(spec.Parameters); err != nil {
		return err
	}
	if spec.SchemaVersion < 2 {
		if err := generictemplate.ValidateRuntimeArgSpecs(spec.RuntimeArgs); err != nil {
			return err
		}
	}
	if err := generictemplate.ValidateTemplateSpecMode(spec); err != nil {
		return err
	}
	return spec.ValidateOpcodeCostDeclaration()
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
	return newProviderFromBase(spec, base, mustTemplateSaltStyle(spec.DerivationVersion))
}

// NewHostProviderFromTemplateSpec composes spec as one of its base key type's
// own programs, as a plain host's bounds are: under the base's identity (spec
// names the base as its key type) and the base's salt style, so it and the plain
// program on the same spending key differ only by the bounded profile. spec gets
// every template check. The base is given rather than looked up, because a host
// builds its programs while it registers, before the base is in the registry.
// Installed templates never reach this: each has an identity of its own.
func NewHostProviderFromTemplateSpec(spec *TemplateSpec, base BaseRegistration, saltStyle lsigsalt.Style) (*ComposedDSA, error) {
	if spec == nil || spec.KeyType() != base.BaseKeyType || spec.BaseKeyType != base.BaseKeyType {
		return nil, fmt.Errorf("a host program must name its base %q as its key type and base", base.BaseKeyType)
	}
	rules := templateBaseRules{
		registered:     func(baseKeyType string) bool { return baseKeyType == base.BaseKeyType },
		allowsCosigner: boundedContractAllowsCosigner,
	}
	if err := validateTemplateSpec(spec, rules); err != nil {
		return nil, err
	}
	return newProviderFromBase(spec, base, saltStyle)
}

// newProviderFromBase composes a validated spec on a resolved base. It does not
// consult the base registry, so tests can compose on a base production never
// registers.
func newProviderFromBase(spec *TemplateSpec, base BaseRegistration, saltStyle lsigsalt.Style) (*ComposedDSA, error) {
	bounded, err := boundedProfileFromTemplate(spec.Bounded)
	if err != nil {
		return nil, err
	}
	layer3, err := layer3PolicyFromTemplate(spec.Bounded, generictemplate.ParameterSpecToParameterDefs(spec.Parameters), bounded, strings.TrimSpace(spec.TEAL) != "")
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
		SaltStyle:          saltStyle,
		TemplateMode:       generictemplate.EffectiveTemplateMode(spec),
		TemplateVars:       spec.TemplateVariables,
		Params:             generictemplate.ParameterSpecToParameterDefs(spec.Parameters),
		RuntimeArgs:        append(generictemplate.RuntimeArgSpecToRuntimeArgDefs(spec.RuntimeArgs), runtimeDefs...),
		BoundedRuntimeArgs: boundedRuntimeMetadata,
		DerivedArgs:        boundedDerivedArgsFromTemplate(spec.Bounded),
		Bounded:            bounded,
		Layer3:             layer3,
		OpcodeProfile:      spec.LogicSigOpcodeProfile(bounded != nil),
		ValidRekeyTarget:   spec.RekeyTargetValid(),
	}), nil
}

// ValidateTemplateAdmission is what a composed template must pass to be
// installed, beyond ValidateTemplateSpec: the checks that apply to a new template
// and never to one already in a store. A store reload builds its templates
// without them, so a template installed before a check existed keeps loading and
// can't take the whole store down. The checks:
//
//   - it declares valid_rekey_target;
//   - its LogicSig arguments fit the network's limits on one LogicSig;
//   - a bounded template satisfies its template-level contract, so a mistake
//     key generation would refuse is refused here first.
func ValidateTemplateAdmission(spec *TemplateSpec) error {
	if err := ValidateTemplateSpec(spec); err != nil {
		return err
	}
	if err := spec.ValidateRekeyTargetDeclaration(); err != nil {
		return err
	}
	if err := generictemplate.ValidateRuntimeArgLimits(spec.RuntimeArgs); err != nil {
		return err
	}
	if spec.Bounded != nil {
		for _, arg := range spec.Bounded.RuntimeArgs {
			// The same refusal, in the same words, as a schema 1 runtime argument.
			if arg.MaxSize > lsigresource.MaxLogicSigArgBytes {
				return fmt.Errorf("runtime_arg %s is %d bytes: a LogicSig argument is at most %d", arg.Name, arg.MaxSize, lsigresource.MaxLogicSigArgBytes)
			}
		}
	}
	provider, err := NewProviderFromTemplateSpec(spec)
	if err != nil {
		return err
	}
	if err := provider.validateTemplateContract(); err != nil {
		return err
	}
	return provider.checkArgumentLimits()
}

// validateTemplateContract checks a bounded template against its template-level
// contract: the profile, the framework's injected parameters, and the argument
// layout's structure. Instance fields, such as a cosigner key, wait for key
// generation.
func (c *ComposedDSA) validateTemplateContract() error {
	if c.bounded == nil {
		return nil
	}
	metadata, err := c.boundedAuthorizationMetadataBase()
	if err != nil {
		return fmt.Errorf("invalid bounded template contract: %w", err)
	}
	if metadata == nil {
		return nil
	}
	if err := metadata.ValidateProfile(); err != nil {
		return fmt.Errorf("invalid bounded template contract: %w", err)
	}
	return nil
}

// checkArgumentLimits refuses a program whose LogicSig the network would refuse
// on any transaction: too many arguments, or one too large. A bounded program's
// whole layout counts (signatures, proofs, runtime arguments and the cosigner's
// signature). Any other composed program has the base's signature arguments and
// the template's runtime arguments.
func (c *ComposedDSA) checkArgumentLimits() error {
	if c.bounded != nil {
		// validateTemplateContract has already built this without error.
		if metadata, err := c.boundedAuthorizationMetadataBase(); err == nil && metadata != nil {
			return metadata.ValidateNetworkLimits()
		}
	}
	// A base that doesn't describe its signature arguments still carries at
	// least one.
	signatureArgs := 1
	if _, described := c.SignatureArgLayout(); described {
		layout, err := c.validatedSignatureArgLayout()
		if err != nil {
			return err
		}
		for i, size := range layout.MaxSizes {
			if size > lsigresource.MaxLogicSigArgBytes {
				return fmt.Errorf("base signature argument %d is %d bytes: a LogicSig argument is at most %d", i, size, lsigresource.MaxLogicSigArgBytes)
			}
		}
		signatureArgs = layout.Count
	}
	if total := signatureArgs + len(c.runtimeArgs); total > lsigresource.MaxLogicSigArgs {
		return fmt.Errorf("%d arguments (%d signature, %d runtime): a LogicSig carries at most %d",
			total, signatureArgs, len(c.runtimeArgs), lsigresource.MaxLogicSigArgs)
	}
	return nil
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
	for _, arg := range spec.RuntimeArgs {
		if isBoundedCosignerReservedName(arg.Name) {
			return fmt.Errorf("bounded.runtime_args argument name %q uses reserved cosigner namespace", arg.Name)
		}
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
		// A rekey never reaches Layer 3, so a runtime argument is spend-only.
		if len(arg.RequiredOn) != 1 || arg.RequiredOn[0] != boundedmeta.PathSpend {
			return fmt.Errorf("bounded.runtime_args argument %q must have required_on [%s]: a rekey never reaches Layer 3", arg.Name, boundedmeta.PathSpend)
		}
	}
	for _, arg := range spec.DerivedArgs {
		if isBoundedCosignerReservedName(arg.Name) {
			return fmt.Errorf("bounded.derived_args argument name %q uses reserved cosigner namespace", arg.Name)
		}
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
	// The plain host is the plain providers' alone: a template is a bounded host.
	if spec.Contract == PlainContract {
		return nil, fmt.Errorf("bounded.contract %s is the plain host's, which templates don't declare", PlainContract)
	}
	if spec.MaxFee == nil {
		return nil, fmt.Errorf("bounded.max_fee is required")
	}
	profile := &BoundedAuthorizationProfile{
		Contract: spec.Contract,
		MaxFee:   new(*spec.MaxFee),
	}
	if spec.Cosigner != nil {
		profile.Cosigner = &boundedmeta.CosignerAuthorization{
			Contract:         spec.Cosigner.Contract,
			ComponentKeyType: boundedmeta.CosignerComponentKeyTypeV1,
			SignatureMaxSize: boundedmeta.CosignerSignatureMaxSizeV1,
			RequiredOn:       append([]string(nil), spec.Cosigner.RequiredOn...),
		}
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
	switch spec.Rekey {
	case "":
		return nil, fmt.Errorf("bounded.rekey is required: %s, %s, %s or %s", boundedmeta.RekeyRefused, boundedmeta.RekeySpendingKey, BoundedRekeyOnlyThese, BoundedRekeyPlusCosigned)
	case BoundedRekeyOnlyThese:
		// Only these addresses: no rekey except to an address on the list, which
		// the framework adds as the rekey_to parameter.
		profile.Rekey = boundedmeta.RekeyRefused
		profile.RekeyList = &boundedmeta.RekeyList{Contract: boundedmeta.RekeyListContractV1, Depth: rekeylist.Depth}
	case BoundedRekeyPlusCosigned:
		// These addresses with the spending key alone, others with the cosigner
		// too; the profile check refuses it without a cosigner.
		profile.Rekey = boundedmeta.RekeySpendingKey
		profile.RekeyList = &boundedmeta.RekeyList{Contract: boundedmeta.RekeyListContractV1, Depth: rekeylist.Depth}
	default:
		profile.Rekey = boundedmeta.RekeySetting(spec.Rekey)
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
	return SpecFingerprint(spec)
}

// SpecFingerprint is SemanticFingerprint for a template already parsed.
func SpecFingerprint(spec *TemplateSpec) (string, error) {
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
