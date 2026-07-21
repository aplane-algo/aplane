// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	boundedmessage "github.com/aplane-algo/aplane/internal/boundedadmin/message"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/tealtemplate"
	"github.com/aplane-algo/aplane/internal/txeffects"
)

// The generation-side vocabulary is defined in terms of boundedmeta, the
// durable storage vocabulary, so the two cannot drift: a contract revision
// edits boundedmeta once and both sides follow at compile time.
const (
	// BoundedContractV1 is the frozen v1 bounded-authorization contract.
	BoundedContractV1 = boundedmeta.ContractV1
	// BoundedMaxFeeV1 is the largest fee a bounded1 profile may compile.
	BoundedMaxFeeV1 uint64 = boundedmeta.MaximumProfileFee
	// BoundedAdminPublicKeyParameter is injected for admin-key profiles.
	BoundedAdminPublicKeyParameter = boundedmeta.AdminPublicKeyParameter
	// BoundedAdminPublicKeySize is the frozen Falcon-1024 public-key size.
	BoundedAdminPublicKeySize = boundedmeta.FalconAdminPublicKeySize
	// BoundedAdminSignatureMaxSize is the frozen Falcon-1024 signature bound.
	BoundedAdminSignatureMaxSize = boundedmeta.FalconAdminSignatureSize

	boundedReservedNamePrefix  = "bounded_"
	boundedReservedLabelPrefix = "__aplane_bounded1_"

	boundedProfileDomainV1            = "APLANE_BOUNDED_PROFILE_V1"
	boundedBehaviorParametersDomainV1 = "APLANE_BOUNDED_BEHAVIOR_PARAMETERS_V1"
	boundedAdminProgramDomainV1       = "APLANE_BOUNDED_ADMIN_PROGRAM_V1"
)

// AdminOperationKind identifies a bounded administrative operation.
type AdminOperationKind string

const (
	AdminOperationRekey AdminOperationKind = boundedmeta.AdminOperationRekey
)

// AdminOperationAuthorization selects the authority required by an operation.
type AdminOperationAuthorization string

const (
	AdminAuthorizationSpendingKey AdminOperationAuthorization = boundedmeta.AdminAuthorizationSpend
	AdminAuthorizationAdminKey    AdminOperationAuthorization = boundedmeta.AdminAuthorizationAdmin
)

// AdminPolicyGate selects whether Layer 3 also constrains an operation.
type AdminPolicyGate string

const (
	AdminPolicyGateNone   AdminPolicyGate = boundedmeta.PolicyGateNone
	AdminPolicyGateLayer3 AdminPolicyGate = boundedmeta.PolicyGateLayer3
)

// AdminOperationSpec enables one exact administrative normal form.
type AdminOperationSpec struct {
	Kind          AdminOperationKind
	Authorization AdminOperationAuthorization
	PolicyGate    AdminPolicyGate
}

// BoundedAuthorizationProfile defines the bounded envelope compiled around
// a composed DSA spending policy.
type BoundedAuthorizationProfile struct {
	Contract        string
	SpendEffects    []txeffects.SpendEffect
	MaxFee          uint64
	AdminOperations []AdminOperationSpec
}

type boundedFingerprint struct {
	CanonicalProfileHex string `json:"canonical_profile_hex"`
}

func cloneBoundedProfile(profile *BoundedAuthorizationProfile) *BoundedAuthorizationProfile {
	if profile == nil {
		return nil
	}
	cloned := *profile
	cloned.SpendEffects = append([]txeffects.SpendEffect(nil), profile.SpendEffects...)
	cloned.AdminOperations = append([]AdminOperationSpec(nil), profile.AdminOperations...)
	return &cloned
}

// validate delegates the bounded1 rule set to boundedmeta so generation and
// storage validation cannot diverge; only the contract/fee comparisons stay
// local, expressed against the aliased shared constants.
func (profile *BoundedAuthorizationProfile) validate() error {
	if profile == nil {
		return nil
	}
	if profile.Contract != BoundedContractV1 {
		return fmt.Errorf("unsupported bounded authorization contract %q", profile.Contract)
	}
	if profile.MaxFee > BoundedMaxFeeV1 {
		return fmt.Errorf("max_fee %d exceeds bounded1 ceiling %d", profile.MaxFee, BoundedMaxFeeV1)
	}
	spendEffects := make([]string, len(profile.SpendEffects))
	for i, effect := range profile.SpendEffects {
		spendEffects[i] = string(effect)
	}
	if err := boundedmeta.ValidateSpendEffects(spendEffects); err != nil {
		return err
	}
	operations := make([]boundedmeta.AdminOperation, len(profile.AdminOperations))
	for i, operation := range profile.AdminOperations {
		operations[i] = boundedmeta.AdminOperation{Kind: string(operation.Kind), Authorization: string(operation.Authorization), PolicyGate: string(operation.PolicyGate)}
	}
	return boundedmeta.ValidateAdminOperations(operations)
}

func canonicalBoundedProfile(profile *BoundedAuthorizationProfile) (*BoundedAuthorizationProfile, error) {
	if profile == nil {
		return nil, nil
	}
	if err := profile.validate(); err != nil {
		return nil, err
	}
	canonical := cloneBoundedProfile(profile)
	canonical.SpendEffects = canonicalSpendEffects(canonical.SpendEffects)
	sort.Slice(canonical.AdminOperations, func(i, j int) bool {
		return canonical.AdminOperations[i].Kind < canonical.AdminOperations[j].Kind
	})
	return canonical, nil
}

func canonicalSpendEffects(effects []txeffects.SpendEffect) []txeffects.SpendEffect {
	selected := make(map[txeffects.SpendEffect]struct{}, len(effects))
	for _, effect := range effects {
		selected[effect] = struct{}{}
	}
	ordered := make([]txeffects.SpendEffect, 0, len(effects))
	for _, effect := range txeffects.Bounded1Manifest().SpendEffects {
		if _, ok := selected[effect]; ok {
			ordered = append(ordered, effect)
		}
	}
	return ordered
}

func boundedFingerprintProjection(profile *BoundedAuthorizationProfile, metadata *boundedmeta.Metadata) any {
	if profile == nil {
		return nil
	}
	encoded, err := CanonicalBoundedProfile(profile, metadata)
	if err != nil {
		return map[string]string{"invalid": err.Error()}
	}
	return boundedFingerprint{CanonicalProfileHex: hex.EncodeToString(encoded)}
}

// CanonicalBoundedProfile encodes a profile using the frozen bounded1 binary
// contract used by program bindings and offline artifacts.
func CanonicalBoundedProfile(profile *BoundedAuthorizationProfile, metadata *boundedmeta.Metadata) ([]byte, error) {
	canonical, err := canonicalBoundedProfile(profile)
	if err != nil {
		return nil, err
	}
	if canonical == nil {
		return nil, fmt.Errorf("bounded profile is required")
	}
	if err := validateCanonicalMetadata(canonical, metadata); err != nil {
		return nil, err
	}
	var encoded []byte
	encoded = boundedmeta.AppendField(encoded, []byte(boundedProfileDomainV1))
	encoded = boundedmeta.AppendField(encoded, []byte(canonical.Contract))
	encoded = boundedmeta.AppendUint32(encoded, uint32(len(canonical.SpendEffects)))
	for _, effect := range canonical.SpendEffects {
		encoded = boundedmeta.AppendField(encoded, []byte(effect))
	}
	encoded = boundedmeta.AppendUint64(encoded, canonical.MaxFee)
	encoded = boundedmeta.AppendUint32(encoded, uint32(len(canonical.AdminOperations)))
	for _, operation := range canonical.AdminOperations {
		encoded = boundedmeta.AppendField(encoded, []byte(operation.Kind))
		encoded = boundedmeta.AppendField(encoded, []byte(operation.Authorization))
		encoded = boundedmeta.AppendField(encoded, []byte(operation.PolicyGate))
	}
	encoded = boundedmeta.AppendField(encoded, []byte(metadata.Layer3Policy))
	encoded = boundedmeta.AppendUint32(encoded, uint32(metadata.BaseSignatureArgLayout.Count))
	for _, maxSize := range metadata.BaseSignatureArgLayout.MaxSizes {
		encoded = boundedmeta.AppendUint32(encoded, uint32(maxSize))
	}
	encoded = boundedmeta.AppendUint32(encoded, uint32(len(metadata.DerivedArgs)))
	for _, arg := range metadata.DerivedArgs {
		encoded = boundedmeta.AppendField(encoded, []byte(arg.Name))
		encoded = boundedmeta.AppendField(encoded, []byte(arg.Kind))
		encoded = boundedmeta.AppendField(encoded, []byte(arg.Parameter))
		encoded = boundedmeta.AppendUint32(encoded, uint32(arg.MaxSize))
	}
	encoded = boundedmeta.AppendUint32(encoded, uint32(len(metadata.RuntimeArgs)))
	for _, arg := range metadata.RuntimeArgs {
		encoded = boundedmeta.AppendField(encoded, []byte(arg.Name))
		encoded = boundedmeta.AppendField(encoded, []byte(arg.Type))
		if arg.Required {
			encoded = boundedmeta.AppendUint32(encoded, 1)
		} else {
			encoded = boundedmeta.AppendUint32(encoded, 0)
		}
		encoded = boundedmeta.AppendUint32(encoded, uint32(arg.ByteLength))
		encoded = boundedmeta.AppendUint32(encoded, uint32(arg.MaxSize))
	}
	encoded = boundedmeta.AppendUint32(encoded, uint32(len(metadata.ArgumentLayout)))
	for _, slot := range metadata.ArgumentLayout {
		encoded = boundedmeta.AppendUint32(encoded, uint32(slot.Index))
		encoded = boundedmeta.AppendField(encoded, []byte(slot.Name))
		encoded = boundedmeta.AppendField(encoded, []byte(slot.Source))
		encoded = boundedmeta.AppendUint32(encoded, uint32(slot.MaxSize))
		encoded = boundedmeta.AppendField(encoded, []byte(slot.Paths.Spend))
		encoded = boundedmeta.AppendField(encoded, []byte(slot.Paths.SpendingRekey))
		encoded = boundedmeta.AppendField(encoded, []byte(slot.Paths.AdminRekey))
	}
	return encoded, nil
}

func validateCanonicalMetadata(profile *BoundedAuthorizationProfile, metadata *boundedmeta.Metadata) error {
	if err := metadata.ValidateProfile(); err != nil {
		return fmt.Errorf("invalid bounded profile metadata: %w", err)
	}
	spendEffects := make([]string, len(profile.SpendEffects))
	for i, effect := range profile.SpendEffects {
		spendEffects[i] = string(effect)
	}
	operations := make([]boundedmeta.AdminOperation, len(profile.AdminOperations))
	for i, operation := range profile.AdminOperations {
		operations[i] = boundedmeta.AdminOperation{
			Kind: string(operation.Kind), Authorization: string(operation.Authorization), PolicyGate: string(operation.PolicyGate),
		}
	}
	if metadata.Contract != profile.Contract || metadata.MaxFee != profile.MaxFee ||
		!slices.Equal(metadata.SpendEffects, spendEffects) || !slices.Equal(metadata.AdminOperations, operations) {
		return fmt.Errorf("bounded profile metadata does not match the authorization profile")
	}
	return nil
}

func boundedRequiresAdminKey(profile *BoundedAuthorizationProfile) bool {
	if profile == nil {
		return false
	}
	for _, operation := range profile.AdminOperations {
		if operation.Authorization == AdminAuthorizationAdminKey {
			return true
		}
	}
	return false
}

func boundedAdminPublicKeyParameterDef() lsigprovider.ParameterDef {
	return lsigprovider.ParameterDef{
		Name:        BoundedAdminPublicKeyParameter,
		Label:       "Contract Admin Public Key",
		Description: "Falcon-1024 public key for bounded authorization contract administration",
		Type:        "bytes",
		Required:    true,
		MaxLength:   BoundedAdminPublicKeySize * 2,
	}
}

func hasParameter(params []lsigprovider.ParameterDef, name string) bool {
	for _, param := range params {
		if param.Name == name {
			return true
		}
	}
	return false
}

func cloneSignatureArgLayout(layout SignatureArgLayout) SignatureArgLayout {
	layout.MaxSizes = append([]int(nil), layout.MaxSizes...)
	return layout
}

func validateSignatureArgLayout(layout SignatureArgLayout) error {
	return boundedmeta.ValidateSignatureLayout(layout)
}

func (c *ComposedDSA) validatedSignatureArgLayout() (SignatureArgLayout, error) {
	layout, ok := c.SignatureArgLayout()
	if !ok {
		return SignatureArgLayout{}, fmt.Errorf("base key type %q does not expose a static bounded signature argument layout", c.baseKeyType)
	}
	if err := validateSignatureArgLayout(layout); err != nil {
		return SignatureArgLayout{}, err
	}
	return layout, nil
}

// BoundedAuthorizationMetadata returns the canonical template-level inventory
// projection. Instance-only fields are populated during key generation.
func (c *ComposedDSA) BoundedAuthorizationMetadata() *boundedmeta.Metadata {
	metadata, err := c.boundedAuthorizationMetadataBase()
	if err != nil {
		return nil
	}
	return metadata
}

// BuildBoundedAuthorizationMetadata snapshots the complete non-secret bounded
// signing contract after program derivation. Existing keys use this durable
// projection and never need the installed YAML template to route or assemble.
func (c *ComposedDSA) BuildBoundedAuthorizationMetadata(publicKey []byte, params map[string]string, bytecode []byte) (*boundedmeta.Metadata, error) {
	metadata, err := c.boundedAuthorizationMetadataBase()
	if err != nil || metadata == nil {
		return metadata, err
	}
	profile := c.bounded
	metadata.PostSigningLogicSigSize = len(bytecode)
	for _, slot := range metadata.ArgumentLayout {
		metadata.PostSigningLogicSigSize += slot.MaxSize
	}

	if boundedRequiresAdminKey(profile) {
		adminPublicKey, err := decodeHexParameter(params[BoundedAdminPublicKeyParameter], BoundedAdminPublicKeyParameter, BoundedAdminPublicKeySize)
		if err != nil {
			return nil, err
		}
		profileEncoding, err := CanonicalBoundedProfile(profile, metadata)
		if err != nil {
			return nil, err
		}
		behaviorEncoding, err := canonicalBehaviorParameters(params, c.params)
		if err != nil {
			return nil, err
		}
		binding := boundedProgramBinding(c.keyType, c.baseKeyType, c.ops.TEALVersion(), publicKey, adminPublicKey, profileEncoding, behaviorEncoding)
		adminKeyID, err := BoundedAdminKeyID(adminPublicKey)
		if err != nil {
			return nil, err
		}
		metadata.AdminPublicKeyHex = hex.EncodeToString(adminPublicKey)
		metadata.AdminKeyID = adminKeyID
		metadata.ProgramBindingHex = hex.EncodeToString(binding[:])
	}
	if err := metadata.Validate(); err != nil {
		return nil, fmt.Errorf("invalid generated bounded metadata: %w", err)
	}
	return metadata, nil
}

func (c *ComposedDSA) boundedAuthorizationMetadataBase() (*boundedmeta.Metadata, error) {
	profile, layout, err := c.validateBoundedConfig()
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, nil
	}
	metadata := &boundedmeta.Metadata{
		Contract: profile.Contract,
		BaseSignatureArgLayout: boundedmeta.SignatureArgLayout{
			Count:    layout.Count,
			MaxSizes: append([]int(nil), layout.MaxSizes...),
		},
		MaxFee:       profile.MaxFee,
		Layer3Policy: layer3PolicyName(c.layer3),
		RuntimeArgs:  append([]boundedmeta.RuntimeArg(nil), c.boundedRuntimeArgs...),
		DerivedArgs:  append([]boundedmeta.DerivedArg(nil), c.derivedArgs...),
	}
	for _, effect := range profile.SpendEffects {
		metadata.SpendEffects = append(metadata.SpendEffects, string(effect))
	}
	for _, operation := range profile.AdminOperations {
		metadata.AdminOperations = append(metadata.AdminOperations, boundedmeta.AdminOperation{
			Kind:          string(operation.Kind),
			Authorization: string(operation.Authorization),
			PolicyGate:    string(operation.PolicyGate),
		})
	}
	metadata.ArgumentLayout = boundedArgumentLayout(layout, profile, metadata.DerivedArgs, metadata.RuntimeArgs)
	return metadata, nil
}

func boundedArgumentLayout(layout SignatureArgLayout, profile *BoundedAuthorizationProfile, derived []boundedmeta.DerivedArg, runtime []boundedmeta.RuntimeArg) []boundedmeta.ArgumentSlot {
	slots := make([]boundedmeta.ArgumentSlot, 0, layout.Count+len(derived)+len(runtime)+1)
	for i, maxSize := range layout.MaxSizes {
		slots = append(slots, boundedmeta.ArgumentSlot{
			Index: i, Name: fmt.Sprintf("base_signature_%d", i), Source: boundedmeta.ArgSourceBaseSignature, MaxSize: maxSize,
			Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: boundedmeta.ArgRequired, AdminRekey: boundedmeta.ArgRequired},
		})
	}
	for _, arg := range derived {
		slots = append(slots, boundedmeta.ArgumentSlot{
			Index: len(slots), Name: arg.Name, Source: boundedmeta.ArgSourceDerived, MaxSize: arg.MaxSize,
			Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgOptional, SpendingRekey: boundedmeta.ArgForbidden, AdminRekey: boundedmeta.ArgForbidden},
		})
	}
	rekeyGate := boundedRekeyUsesLayer3(profile)
	for _, arg := range runtime {
		rekeyRule := boundedmeta.ArgForbidden
		if rekeyGate {
			rekeyRule = boundedmeta.ArgRequired
		}
		slots = append(slots, boundedmeta.ArgumentSlot{
			Index: len(slots), Name: arg.Name, Source: boundedmeta.ArgSourceRuntime, MaxSize: arg.MaxSize,
			Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: rekeyRule, AdminRekey: boundedmeta.ArgForbidden},
		})
	}
	if boundedRequiresAdminKey(profile) {
		slots = append(slots, boundedmeta.ArgumentSlot{
			Index: len(slots), Name: "admin_signature", Source: boundedmeta.ArgSourceAdmin, MaxSize: BoundedAdminSignatureMaxSize,
			Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgForbidden, SpendingRekey: boundedmeta.ArgForbidden, AdminRekey: boundedmeta.ArgRequired},
		})
	}
	return slots
}

func boundedRekeyUsesLayer3(profile *BoundedAuthorizationProfile) bool {
	for _, operation := range profile.AdminOperations {
		if operation.Kind == AdminOperationRekey && operation.Authorization == AdminAuthorizationSpendingKey && operation.PolicyGate == AdminPolicyGateLayer3 {
			return true
		}
	}
	return false
}

func validateBuiltSignatureArgs(args [][]byte, layout SignatureArgLayout) error {
	if len(args) != layout.Count {
		return fmt.Errorf("base emitted %d signature args, bounded layout requires %d", len(args), layout.Count)
	}
	for i, arg := range args {
		if len(arg) == 0 || len(arg) > layout.MaxSizes[i] {
			return fmt.Errorf("base signature arg %d length %d invalid (expected 1..%d bytes)", i, len(arg), layout.MaxSizes[i])
		}
	}
	return nil
}

func (c *ComposedDSA) validateBoundedConfig() (*BoundedAuthorizationProfile, SignatureArgLayout, error) {
	profile, err := canonicalBoundedProfile(c.bounded)
	if err != nil {
		return nil, SignatureArgLayout{}, err
	}
	if profile == nil {
		return nil, SignatureArgLayout{}, nil
	}
	if c.layer3 == nil && strings.TrimSpace(c.tealSuffix) == "" {
		return nil, SignatureArgLayout{}, fmt.Errorf("bounded1 requires a Layer-3 spending policy suffix")
	}
	if c.layer3 != nil && strings.TrimSpace(c.tealSuffix) != "" {
		return nil, SignatureArgLayout{}, fmt.Errorf("framework-owned bounded Layer-3 policy must not include author TEAL")
	}
	if err := validateLayer3Policy(c.layer3, c.paramsWithoutAdminKey(), profile); err != nil {
		return nil, SignatureArgLayout{}, fmt.Errorf("invalid bounded Layer-3 policy: %w", err)
	}
	if c.ops.TEALVersion() != txeffects.Bounded1Manifest().TEALVersion {
		return nil, SignatureArgLayout{}, fmt.Errorf("bounded1 requires TEAL version %d, base emits version %d", txeffects.Bounded1Manifest().TEALVersion, c.ops.TEALVersion())
	}
	if len(c.runtimeArgs) != len(c.boundedRuntimeArgs) {
		return nil, SignatureArgLayout{}, fmt.Errorf("bounded1 runtime arguments must use the bounded argument contract")
	}
	for i, arg := range c.runtimeArgs {
		metadataArg := c.boundedRuntimeArgs[i]
		if arg.Name != metadataArg.Name || arg.Type != metadataArg.Type || arg.Required != metadataArg.Required ||
			arg.ByteLength != metadataArg.ByteLength || arg.MaxSize != metadataArg.MaxSize {
			return nil, SignatureArgLayout{}, fmt.Errorf("bounded1 runtime argument %q does not match its metadata contract", arg.Name)
		}
	}
	if err := validateBoundedReservedNames(profile, c.params, c.runtimeArgs, c.templateVars, c.tealSuffix); err != nil {
		return nil, SignatureArgLayout{}, err
	}
	layout, err := c.validatedSignatureArgLayout()
	if err != nil {
		return nil, SignatureArgLayout{}, err
	}
	return profile, layout, nil
}

func layer3PolicyName(policy *Layer3Policy) string {
	if policy == nil {
		return boundedmeta.Layer3PolicyCustom
	}
	return policy.Policy
}

func validateBoundedReservedNames(profile *BoundedAuthorizationProfile, params []lsigprovider.ParameterDef, runtimeArgs []lsigprovider.RuntimeArgDef, templateVars []tealtemplate.TemplateVariable, teal string) error {
	for _, param := range params {
		if !strings.HasPrefix(param.Name, boundedReservedNamePrefix) {
			continue
		}
		if param.Name != BoundedAdminPublicKeyParameter || !boundedRequiresAdminKey(profile) {
			return fmt.Errorf("parameter name %q uses reserved bounded_ prefix", param.Name)
		}
		want := boundedAdminPublicKeyParameterDef()
		if param.Type != want.Type || !param.Required || param.MaxLength != want.MaxLength {
			return fmt.Errorf("parameter %q does not match the framework-injected contract", param.Name)
		}
	}
	for _, arg := range runtimeArgs {
		if strings.HasPrefix(arg.Name, boundedReservedNamePrefix) {
			return fmt.Errorf("runtime arg name %q uses reserved bounded_ prefix", arg.Name)
		}
	}
	for _, variable := range templateVars {
		if strings.HasPrefix(variable.Name, boundedReservedNamePrefix) {
			return fmt.Errorf("template variable name %q uses reserved bounded_ prefix", variable.Name)
		}
		if strings.HasPrefix(variable.Parameter, boundedReservedNamePrefix) {
			return fmt.Errorf("template variable %q references reserved bounded parameter %q", variable.Name, variable.Parameter)
		}
	}
	for _, line := range strings.Split(teal, "\n") {
		if comment := strings.Index(line, "//"); comment >= 0 {
			line = line[:comment]
		}
		for _, token := range strings.Fields(line) {
			if strings.Contains(token, boundedReservedLabelPrefix) {
				return fmt.Errorf("author TEAL uses reserved bounded label identifier %q", token)
			}
			if strings.HasPrefix(strings.TrimPrefix(token, "@"), boundedReservedNamePrefix) {
				return fmt.Errorf("author TEAL uses reserved bounded identifier %q", token)
			}
		}
	}
	return nil
}

func decodeHexParameter(value, name string, expectedSize int) ([]byte, error) {
	value = strings.TrimSpace(strings.TrimPrefix(value, "0x"))
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid %s hex: %w", name, err)
	}
	if expectedSize > 0 && len(decoded) != expectedSize {
		return nil, fmt.Errorf("%s length %d invalid (expected %d bytes)", name, len(decoded), expectedSize)
	}
	return decoded, nil
}

func canonicalBehaviorParameters(params map[string]string, defs []lsigprovider.ParameterDef) ([]byte, error) {
	normalized, err := lsigprovider.NormalizeCreationParams(params, defs)
	if err != nil {
		return nil, fmt.Errorf("normalize behavior parameters: %w", err)
	}

	var encoded []byte
	encoded = boundedmeta.AppendField(encoded, []byte(boundedBehaviorParametersDomainV1))
	count := 0
	for _, def := range defs {
		if def.Name != BoundedAdminPublicKeyParameter {
			count++
		}
	}
	encoded = boundedmeta.AppendUint32(encoded, uint32(count))
	for _, def := range defs {
		if def.Name == BoundedAdminPublicKeyParameter {
			continue
		}
		value, present := normalized[def.Name]
		var canonical []byte
		if def.Required || (present && value != "") {
			canonical, err = canonicalParameterValue(def, value)
			if err != nil {
				return nil, fmt.Errorf("canonical parameter %s: %w", def.Name, err)
			}
		}
		encoded = boundedmeta.AppendField(encoded, []byte(def.Name))
		encoded = boundedmeta.AppendField(encoded, []byte(def.Type))
		encoded = boundedmeta.AppendField(encoded, canonical)
	}
	return encoded, nil
}

// CanonicalBoundedBehaviorParameters encodes behavior-bearing creation values
// in parameter-definition order. The injected admin public key is excluded.
func CanonicalBoundedBehaviorParameters(params map[string]string, defs []lsigprovider.ParameterDef) ([]byte, error) {
	return canonicalBehaviorParameters(params, defs)
}

func canonicalParameterValue(def lsigprovider.ParameterDef, value string) ([]byte, error) {
	switch def.Type {
	case "address":
		address, err := types.DecodeAddress(strings.TrimSpace(value))
		if err != nil {
			return nil, err
		}
		return address[:], nil
	case "bytes":
		return decodeHexParameter(value, def.Name, 0)
	case "uint64":
		number, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return nil, err
		}
		return boundedmeta.AppendUint64(nil, number), nil
	case "address[]":
		items := splitCanonicalList(value)
		encoded := boundedmeta.AppendUint32(nil, uint32(len(items)))
		for _, item := range items {
			address, err := types.DecodeAddress(item)
			if err != nil {
				return nil, err
			}
			encoded = boundedmeta.AppendField(encoded, address[:])
		}
		return encoded, nil
	case "uint64[]":
		items := splitCanonicalList(value)
		encoded := boundedmeta.AppendUint32(nil, uint32(len(items)))
		for _, item := range items {
			number, err := strconv.ParseUint(item, 10, 64)
			if err != nil {
				return nil, err
			}
			encoded = boundedmeta.AppendField(encoded, boundedmeta.AppendUint64(nil, number))
		}
		return encoded, nil
	case "string":
		return []byte(value), nil
	case "bool":
		value, err := strconv.ParseBool(strings.TrimSpace(value))
		if err != nil {
			return nil, err
		}
		if value {
			return []byte{1}, nil
		}
		return []byte{0}, nil
	default:
		return nil, fmt.Errorf("unsupported parameter type %q", def.Type)
	}
}

func splitCanonicalList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func boundedProgramBinding(keyType, baseKeyType string, tealVersion int, spendingPublicKey, adminPublicKey, profileEncoding, behaviorEncoding []byte) [sha512.Size256]byte {
	var encoded []byte
	encoded = boundedmeta.AppendField(encoded, []byte(boundedAdminProgramDomainV1))
	encoded = boundedmeta.AppendField(encoded, []byte(BoundedContractV1))
	encoded = boundedmeta.AppendField(encoded, []byte(keyType))
	encoded = boundedmeta.AppendField(encoded, []byte(boundedBasePrimitive(baseKeyType)))
	encoded = boundedmeta.AppendField(encoded, boundedmeta.AppendUint64(nil, uint64(tealVersion)))
	encoded = boundedmeta.AppendField(encoded, spendingPublicKey)
	encoded = boundedmeta.AppendField(encoded, adminPublicKey)
	encoded = boundedmeta.AppendField(encoded, profileEncoding)
	encoded = boundedmeta.AppendField(encoded, behaviorEncoding)
	return sha512.Sum512_256(encoded)
}

func boundedBasePrimitive(baseKeyType string) string {
	normalized := strings.ToLower(strings.TrimSpace(baseKeyType))
	switch normalized {
	case "aplane.falcon1024.v1":
		return "falcon1024"
	case "aplane.ed25519.v1", "aplane.ed25519lsig.v1":
		return "ed25519"
	default:
		return normalized
	}
}

// BoundedProgramBinding derives the immutable bounded1 account binding.
func BoundedProgramBinding(keyType, baseKeyType string, tealVersion int, spendingPublicKey, adminPublicKey, profileEncoding, behaviorEncoding []byte) [sha512.Size256]byte {
	return boundedProgramBinding(keyType, baseKeyType, tealVersion, spendingPublicKey, adminPublicKey, profileEncoding, behaviorEncoding)
}

// BoundedAdminKeyID derives the display identifier for a Falcon contract-admin
// public key.
func BoundedAdminKeyID(adminPublicKey []byte) (string, error) {
	return boundedmeta.AdminKeyID(adminPublicKey)
}

// BoundedAdminMessage returns the exact digest signed for a bounded1 admin
// operation.
func BoundedAdminMessage(operation AdminOperationKind, binding [sha512.Size256]byte, transactionID []byte) ([sha512.Size256]byte, error) {
	return boundedmessage.AdminMessage(string(operation), binding[:], transactionID)
}
