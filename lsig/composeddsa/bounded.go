// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
	"github.com/aplane-algo/aplane/internal/tealtemplate"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/internal/witness"
)

// The generation-side vocabulary is defined in terms of boundedmeta, the
// durable storage vocabulary, so the two cannot drift: a contract revision
// edits boundedmeta once and both sides follow at compile time.
const (
	// BoundedContract is the bounded-authorization contract.
	BoundedContract = boundedmeta.Contract
	// PlainContract is the plain host: signatures and overlays, no host rules.
	PlainContract = boundedmeta.PlainContract
	// BoundedMaxFee is the largest fee a bounded profile may compile.
	BoundedMaxFee uint64 = boundedmeta.MaximumProfileFee
	// BoundedCosignerPublicKeyParameter is injected for cosigner-enabled profiles.
	BoundedCosignerPublicKeyParameter = boundedmeta.CosignerPublicKeyParameter
	// BoundedRekeyToParameter carries a rekey-to list's entries. The framework
	// injects it for a profile with a list; a template that declares it must
	// match the injected definition exactly.
	BoundedRekeyToParameter = boundedmeta.RekeyListEntriesParameter
	// BoundedRekeyOnlyThese is the template's rekey value for a rekey-to list:
	// rekey: refused, plus the list.
	BoundedRekeyOnlyThese = boundedmeta.RekeyOnlyThese
	// BoundedRekeyPlusCosigned is the template's rekey value for a rekey-to list
	// beside cosigned rekeys: rekey: spending_key, plus the list, with a cosigner.
	BoundedRekeyPlusCosigned = boundedmeta.RekeyPlusCosigned

	boundedReservedNamePrefix  = "bounded_"
	boundedReservedLabelPrefix = "__aplane_bounded1_"

	boundedProfileDomain              = "APLANE_BOUNDED_PROFILE_V2"
	boundedBehaviorParametersDomainV1 = "APLANE_BOUNDED_BEHAVIOR_PARAMETERS_V1"
)

// BoundedAuthorizationProfile defines the bounded envelope compiled around
// a composed DSA spending policy. Under the plain contract there is no
// envelope: no spend effects and no fee ceiling, only the rekey dispatch and
// the overlays.
type BoundedAuthorizationProfile struct {
	Contract     string
	SpendEffects []txeffects.SpendEffect
	// MaxFee is the bounded host's fee ceiling, nil on a plain host.
	MaxFee *uint64
	Rekey  boundedmeta.RekeySetting
	// RekeyList is the template-level rekey-to list record; the root is filled
	// in at generation.
	RekeyList *boundedmeta.RekeyList
	Cosigner  *boundedmeta.CosignerAuthorization
}

type boundedFingerprint struct {
	CanonicalProfileHex string `json:"canonical_profile_hex"`
}

func cloneBoundedProfile(profile *BoundedAuthorizationProfile) *BoundedAuthorizationProfile {
	if profile == nil {
		return nil
	}
	cloned := *profile
	cloned.MaxFee = boundedmeta.CloneMaxFee(profile.MaxFee)
	cloned.SpendEffects = append([]txeffects.SpendEffect(nil), profile.SpendEffects...)
	if profile.Cosigner != nil {
		cosigner := *profile.Cosigner
		cosigner.RequiredOn = slices.Clone(profile.Cosigner.RequiredOn)
		cloned.Cosigner = &cosigner
	}
	if profile.RekeyList != nil {
		list := *profile.RekeyList
		cloned.RekeyList = &list
	}
	return &cloned
}

// validate delegates the bounded rule set to boundedmeta so generation and
// storage validation cannot diverge; only the contract/fee comparisons stay
// local, expressed against the aliased shared constants.
func (profile *BoundedAuthorizationProfile) validate() error {
	if profile == nil {
		return nil
	}
	spendEffects := make([]string, len(profile.SpendEffects))
	for i, effect := range profile.SpendEffects {
		spendEffects[i] = string(effect)
	}
	switch profile.Contract {
	case BoundedContract:
		if profile.MaxFee == nil {
			return fmt.Errorf("%s requires max_fee", BoundedContract)
		}
		if *profile.MaxFee > BoundedMaxFee {
			return fmt.Errorf("max_fee %d exceeds %s ceiling %d", *profile.MaxFee, BoundedContract, BoundedMaxFee)
		}
		if err := boundedmeta.ValidateSpendEffects(spendEffects); err != nil {
			return err
		}
	case PlainContract:
		if profile.MaxFee != nil {
			return fmt.Errorf("%s has no fee ceiling: max_fee must be absent", PlainContract)
		}
		if len(spendEffects) != 0 {
			return fmt.Errorf("%s declares no spend effects: every transaction that doesn't rekey is a spend", PlainContract)
		}
	default:
		return fmt.Errorf("unsupported bounded authorization contract %q", profile.Contract)
	}
	if err := boundedmeta.ValidateRekeySetting(profile.Rekey); err != nil {
		return err
	}
	// Plus cosigned needs the cosigner: alone, the spending key already rekeys
	// anywhere, so the list would add nothing.
	if profile.RekeyList != nil && profile.Rekey == boundedmeta.RekeySpendingKey && profile.Cosigner == nil {
		return fmt.Errorf("a rekey-to list beside a spending-key rekey (%s) needs a cosigner", boundedmeta.RekeyPlusCosigned)
	}
	if err := boundedmeta.ValidateCosignerAuthorizationProfile(profile.Cosigner, profile.Rekey); err != nil {
		return err
	}
	return nil
}

// validatedBoundedProfile canonicalizes a profile and checks it against its
// metadata, which catches contradictions such as a rekey-to list beside a
// spending-key rekey without a cosigner. CanonicalBoundedProfile encodes the
// result.
func validatedBoundedProfile(profile *BoundedAuthorizationProfile, metadata *boundedmeta.Metadata) (*BoundedAuthorizationProfile, error) {
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
	return canonical, nil
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
	return canonical, nil
}

func canonicalSpendEffects(effects []txeffects.SpendEffect) []txeffects.SpendEffect {
	selected := make(map[txeffects.SpendEffect]struct{}, len(effects))
	for _, effect := range effects {
		selected[effect] = struct{}{}
	}
	ordered := make([]txeffects.SpendEffect, 0, len(effects))
	for _, effect := range txeffects.BoundedManifest().SpendEffects {
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

// CanonicalBoundedProfile encodes a profile using the bounded binary contract,
// which template fingerprints and the plain hosts' boundary digest hash.
func CanonicalBoundedProfile(profile *BoundedAuthorizationProfile, metadata *boundedmeta.Metadata) ([]byte, error) {
	canonical, err := validatedBoundedProfile(profile, metadata)
	if err != nil {
		return nil, err
	}
	var encoded []byte
	encoded = boundedmeta.AppendField(encoded, []byte(boundedProfileDomain))
	encoded = boundedmeta.AppendField(encoded, []byte(canonical.Contract))
	encoded = boundedmeta.AppendUint32(encoded, uint32(len(canonical.SpendEffects)))
	for _, effect := range canonical.SpendEffects {
		encoded = boundedmeta.AppendField(encoded, []byte(effect))
	}
	// The contract name leads the encoding, so a plain host's has no fee field
	// rather than a placeholder, and a bounded host's encoding is unchanged.
	if canonical.MaxFee != nil {
		encoded = boundedmeta.AppendUint64(encoded, *canonical.MaxFee)
	}
	encoded = boundedmeta.AppendField(encoded, []byte(canonical.Rekey))
	// The list's contract and depth, never its root: the root is an instance
	// value, and the review digest binds the entries it comes from instead.
	if canonical.RekeyList == nil {
		encoded = boundedmeta.AppendUint32(encoded, 0)
	} else {
		encoded = boundedmeta.AppendUint32(encoded, 1)
		encoded = boundedmeta.AppendField(encoded, []byte(canonical.RekeyList.Contract))
		encoded = boundedmeta.AppendUint32(encoded, uint32(canonical.RekeyList.Depth))
	}
	if canonical.Cosigner == nil {
		encoded = boundedmeta.AppendUint32(encoded, 0)
	} else {
		encoded = boundedmeta.AppendUint32(encoded, 1)
		encoded = boundedmeta.AppendField(encoded, []byte(canonical.Cosigner.Contract))
		encoded = boundedmeta.AppendField(encoded, []byte(canonical.Cosigner.ComponentKeyType))
		encoded = boundedmeta.AppendUint32(encoded, uint32(canonical.Cosigner.SignatureMaxSize))
		encoded = boundedmeta.AppendUint32(encoded, uint32(len(canonical.Cosigner.RequiredOn)))
		for _, path := range canonical.Cosigner.RequiredOn {
			encoded = boundedmeta.AppendField(encoded, []byte(path))
		}
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
		encoded = boundedmeta.AppendField(encoded, []byte(slot.Paths.ListedRekey))
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
	if metadata.Contract != profile.Contract || !boundedmeta.EqualMaxFee(metadata.MaxFee, profile.MaxFee) ||
		!slices.Equal(metadata.SpendEffects, spendEffects) || metadata.Rekey != profile.Rekey ||
		!equalCosignerProfile(metadata.Cosigner, profile.Cosigner) || !equalRekeyListProfile(metadata.RekeyList, profile.RekeyList) {
		return fmt.Errorf("bounded profile metadata does not match the authorization profile")
	}
	return nil
}

// equalRekeyListProfile compares the list's definition; the root is the
// instance's and only the metadata has it.
func equalRekeyListProfile(a, b *boundedmeta.RekeyList) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Contract == b.Contract && a.Depth == b.Depth
}

func equalCosignerProfile(a, b *boundedmeta.CosignerAuthorization) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Contract == b.Contract && a.ComponentKeyType == b.ComponentKeyType &&
		a.SignatureMaxSize == b.SignatureMaxSize && slices.Equal(a.RequiredOn, b.RequiredOn)
}

// BoundedCosignerParameterDef returns the definition of the cosigner key the
// composer injects, for a provider that presents it itself.
func BoundedCosignerParameterDef() lsigprovider.ParameterDef {
	return boundedCosignerPublicKeyParameterDef()
}

func boundedCosignerPublicKeyParameterDef() lsigprovider.ParameterDef {
	return lsigprovider.ParameterDef{
		Name:        BoundedCosignerPublicKeyParameter,
		Label:       "Cosigner Public Key",
		Description: "Falcon-1024 public key for bounded spend authorization",
		Type:        "bytes",
		Required:    true,
		MaxLength:   boundedmeta.CosignerPublicKeySizeV1 * 2,
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
	if profile.Cosigner != nil {
		cosignerPublicKey, err := decodeHexParameter(params[BoundedCosignerPublicKeyParameter], BoundedCosignerPublicKeyParameter, boundedmeta.CosignerPublicKeySizeV1)
		if err != nil {
			return nil, err
		}
		if err := c.refuseSharedSpendingKey("cosigner", publicKey, profile.Cosigner.ComponentKeyType, cosignerPublicKey); err != nil {
			return nil, err
		}
		componentKeyID, err := witness.ID(profile.Cosigner.ComponentKeyType, cosignerPublicKey)
		if err != nil {
			return nil, err
		}
		metadata.Cosigner.PublicKeyHex = hex.EncodeToString(cosignerPublicKey)
		metadata.Cosigner.ComponentKeyID = componentKeyID
	}
	if profile.RekeyList != nil {
		root, err := rekeyListRoot(params)
		if err != nil {
			return nil, err
		}
		metadata.RekeyList.RootHex = hex.EncodeToString(root)
	}

	if err := metadata.Validate(); err != nil {
		return nil, fmt.Errorf("invalid generated bounded metadata: %w", err)
	}
	return metadata, nil
}

// spendingKeyHolds reports whether a witness key is the spending key or one of its
// components. The witness's construction comes from its key type, as rendering
// resolves it, so no algorithm is assumed here. An unknown witness key type is an
// error, not "no overlap".
func (c *ComposedDSA) spendingKeyHolds(spendingPublicKey []byte, witnessKeyType string, witnessPublicKey []byte) (bool, error) {
	if bytes.Equal(spendingPublicKey, witnessPublicKey) {
		return true, nil
	}
	witnessConstruction, ok := sigconstruction.ForWitnessKeyType(witnessKeyType)
	if !ok {
		return false, fmt.Errorf("witness key type %q has no signature construction", witnessKeyType)
	}
	return sigconstruction.SharesComponentKey(c.ops.Construction(), spendingPublicKey, witnessConstruction, witnessPublicKey), nil
}

// refuseSharedSpendingKey wraps spendingKeyHolds with the role-specific refusal.
func (c *ComposedDSA) refuseSharedSpendingKey(role string, spendingPublicKey []byte, witnessKeyType string, witnessPublicKey []byte) error {
	shared, err := c.spendingKeyHolds(spendingPublicKey, witnessKeyType, witnessPublicKey)
	if err != nil {
		return err
	}
	if shared {
		return fmt.Errorf("bounded %s witness key must differ from the spending key", role)
	}
	return nil
}

func (c *ComposedDSA) validatedCosignerPublicKey(spendingPublicKey []byte, params map[string]string) ([]byte, error) {
	cosignerPublicKey, err := decodeHexParameter(params[BoundedCosignerPublicKeyParameter], BoundedCosignerPublicKeyParameter, boundedmeta.CosignerPublicKeySizeV1)
	if err != nil {
		return nil, err
	}
	if c.bounded == nil || c.bounded.Cosigner == nil {
		return nil, fmt.Errorf("composer declares no bounded cosigner")
	}
	if err := c.refuseSharedSpendingKey("cosigner", spendingPublicKey, c.bounded.Cosigner.ComponentKeyType, cosignerPublicKey); err != nil {
		return nil, err
	}
	return cosignerPublicKey, nil
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
		MaxFee:       boundedmeta.CloneMaxFee(profile.MaxFee),
		Layer3Policy: c.Layer3PolicyName(),
		RuntimeArgs:  append([]boundedmeta.RuntimeArg(nil), c.boundedRuntimeArgs...),
		DerivedArgs:  append([]boundedmeta.DerivedArg(nil), c.derivedArgs...),
	}
	if profile.RekeyList != nil {
		list := *profile.RekeyList
		metadata.RekeyList = &list
		// After Layer 3's derived arguments, so their indexes don't move.
		metadata.DerivedArgs = append(metadata.DerivedArgs, rekeyListProofArg())
	}
	if profile.Cosigner != nil {
		cosigner := *profile.Cosigner
		cosigner.RequiredOn = slices.Clone(profile.Cosigner.RequiredOn)
		metadata.Cosigner = &cosigner
	}
	for _, effect := range profile.SpendEffects {
		metadata.SpendEffects = append(metadata.SpendEffects, string(effect))
	}
	metadata.Rekey = profile.Rekey
	metadata.ArgumentLayout = boundedArgumentLayout(layout, profile, metadata.DerivedArgs, metadata.RuntimeArgs)
	return metadata, nil
}

func boundedArgumentLayout(layout SignatureArgLayout, profile *BoundedAuthorizationProfile, derived []boundedmeta.DerivedArg, runtime []boundedmeta.RuntimeArg) []boundedmeta.ArgumentSlot {
	slots := make([]boundedmeta.ArgumentSlot, 0, layout.Count+len(derived)+len(runtime)+2)
	for i, maxSize := range layout.MaxSizes {
		slots = append(slots, boundedmeta.ArgumentSlot{
			Index: i, Name: fmt.Sprintf("base_signature_%d", i), Source: boundedmeta.ArgSourceBaseSignature, MaxSize: maxSize,
			Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: boundedmeta.ArgRequired, ListedRekey: boundedmeta.ArgRequired},
		})
	}
	for _, arg := range derived {
		// A recipient proof serves Layer 3, which no rekey reaches; a list proof
		// serves the listed rekey alone.
		paths := boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgOptional, SpendingRekey: boundedmeta.ArgForbidden, ListedRekey: boundedmeta.ArgForbidden}
		if arg.Kind == boundedmeta.DerivedArgRekeyListProof {
			paths = boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgForbidden, SpendingRekey: boundedmeta.ArgForbidden, ListedRekey: boundedmeta.ArgRequired}
		}
		slots = append(slots, boundedmeta.ArgumentSlot{
			Index: len(slots), Name: arg.Name, Source: boundedmeta.ArgSourceDerived, MaxSize: arg.MaxSize, Paths: paths,
		})
	}
	// A rekey never reaches Layer 3, so its arguments are spend-only.
	for _, arg := range runtime {
		slots = append(slots, boundedmeta.ArgumentSlot{
			Index: len(slots), Name: arg.Name, Source: boundedmeta.ArgSourceRuntime, MaxSize: arg.MaxSize,
			Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: boundedmeta.ArgForbidden, ListedRekey: boundedmeta.ArgForbidden},
		})
	}
	if profile.Cosigner != nil {
		slots = append(slots, boundedmeta.ArgumentSlot{
			Index: len(slots), Name: boundedmeta.CosignerSignatureSlot, Source: boundedmeta.ArgSourceCosigner,
			MaxSize: profile.Cosigner.SignatureMaxSize,
			Paths:   boundedmeta.CosignerSlotPaths(profile.Cosigner),
		})
	}
	return slots
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
	switch {
	case profile.Contract == PlainContract:
		// A plain host has no spending rule: Layer 3 is none, and no author TEAL.
		if c.layer3 == nil || c.layer3.Policy != Layer3PolicyNone || c.hasAuthorTEAL() {
			return nil, SignatureArgLayout{}, fmt.Errorf("a %s profile takes layer3 policy %s and no author TEAL", PlainContract, Layer3PolicyNone)
		}
	case c.layer3 == nil && strings.TrimSpace(c.tealSuffix) == "":
		return nil, SignatureArgLayout{}, fmt.Errorf("a bounded profile requires a Layer-3 spending policy suffix")
	}
	if err := c.validateFrameworkLayer3Arguments(); err != nil {
		return nil, SignatureArgLayout{}, fmt.Errorf("invalid bounded Layer-3 arguments: %w", err)
	}
	if err := validateLayer3Policy(c.layer3, c.paramsWithoutCosignerKey(), profile, c.hasAuthorTEAL()); err != nil {
		return nil, SignatureArgLayout{}, fmt.Errorf("invalid bounded Layer-3 policy: %w", err)
	}
	tealVersion := txeffects.BoundedManifest().TEALVersion
	if profile.Contract == PlainContract {
		tealVersion = txeffects.PlainManifest().TEALVersion
	}
	if c.ops.TEALVersion() != tealVersion {
		return nil, SignatureArgLayout{}, fmt.Errorf("a %s profile requires TEAL version %d, base emits version %d", profile.Contract, tealVersion, c.ops.TEALVersion())
	}
	if len(c.runtimeArgs) != len(c.boundedRuntimeArgs) {
		return nil, SignatureArgLayout{}, fmt.Errorf("bounded runtime arguments must use the bounded argument contract")
	}
	for i, arg := range c.runtimeArgs {
		metadataArg := c.boundedRuntimeArgs[i]
		if arg.Name != metadataArg.Name || arg.Type != metadataArg.Type || arg.Required != metadataArg.Required ||
			arg.ByteLength != metadataArg.ByteLength || arg.MaxSize != metadataArg.MaxSize {
			return nil, SignatureArgLayout{}, fmt.Errorf("bounded runtime argument %q does not match its metadata contract", arg.Name)
		}
	}
	if err := validateBoundedReservedNames(profile, c.params, c.runtimeArgs, c.derivedArgs, c.templateVars, c.tealSuffix); err != nil {
		return nil, SignatureArgLayout{}, err
	}
	layout, err := c.validatedSignatureArgLayout()
	if err != nil {
		return nil, SignatureArgLayout{}, err
	}
	return profile, layout, nil
}

func layer3PolicyName(policy *Layer3Policy, hasAuthorTEAL bool) string {
	if policy == nil {
		return boundedmeta.Layer3PolicyCustom
	}
	return boundedmeta.StoredLayer3Policy(policy.Policy, hasAuthorTEAL)
}

func validateBoundedReservedNames(profile *BoundedAuthorizationProfile, params []lsigprovider.ParameterDef, runtimeArgs []lsigprovider.RuntimeArgDef, derivedArgs []boundedmeta.DerivedArg, templateVars []tealtemplate.TemplateVariable, teal string) error {
	for _, param := range params {
		if isBoundedCosignerReservedName(param.Name) {
			if param.Name != BoundedCosignerPublicKeyParameter || profile.Cosigner == nil {
				return fmt.Errorf("parameter name %q uses reserved cosigner namespace", param.Name)
			}
			want := boundedCosignerPublicKeyParameterDef()
			if param.Type != want.Type || !param.Required || param.MaxLength != want.MaxLength {
				return fmt.Errorf("parameter %q does not match the framework-injected contract", param.Name)
			}
			continue
		}
		if param.Name == BoundedRekeyToParameter && profile.RekeyList != nil {
			want := rekeyListEntriesParameterDef(profile.Rekey)
			if param.Type != want.Type || !param.Required || param.MinItems != want.MinItems || param.MaxItems != want.MaxItems {
				return fmt.Errorf("parameter %q does not match the framework-injected contract", param.Name)
			}
			continue
		}
		if !strings.HasPrefix(param.Name, boundedReservedNamePrefix) {
			continue
		}
		return fmt.Errorf("parameter name %q uses reserved bounded_ prefix", param.Name)
	}
	for _, arg := range runtimeArgs {
		if isBoundedCosignerReservedName(arg.Name) {
			return fmt.Errorf("runtime arg name %q uses reserved cosigner namespace", arg.Name)
		}
		if strings.HasPrefix(arg.Name, boundedReservedNamePrefix) {
			return fmt.Errorf("runtime arg name %q uses reserved bounded_ prefix", arg.Name)
		}
	}
	// The rekey-to list is private: the program commits only to its root, so no
	// author TEAL may read the entries, and no derived argument may prove one: a
	// recipient-tree proof is unsalted, so a spend would publish siblings anyone
	// can test guessed addresses against. The framework's own list proof is
	// salted and added after this check.
	listPrivate := func(name string) bool { return profile.RekeyList != nil && name == BoundedRekeyToParameter }
	for _, arg := range derivedArgs {
		if listPrivate(arg.Parameter) {
			return fmt.Errorf("derived argument %q would publish proofs over the private rekey-to list", arg.Name)
		}
	}
	for _, variable := range templateVars {
		if listPrivate(variable.Name) || listPrivate(variable.Parameter) {
			return fmt.Errorf("template variable %q would compile the private rekey-to list into the program", variable.Name)
		}
		if isBoundedCosignerReservedName(variable.Name) || isBoundedCosignerReservedName(variable.Parameter) {
			return fmt.Errorf("template variable %q uses reserved cosigner namespace", variable.Name)
		}
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
			if listPrivate(strings.Trim(token, "{}.@")) {
				return fmt.Errorf("author TEAL reads %q, which would compile the private rekey-to list into the program", token)
			}
		}
	}
	return nil
}

func isBoundedCosignerReservedName(name string) bool {
	return name == "cosigner" || strings.HasPrefix(name, "cosigner_")
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
	encoded = boundedmeta.AppendUint32(encoded, uint32(len(defs)))
	for _, def := range defs {
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
// in parameter-definition order.
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
