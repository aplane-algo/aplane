// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/hostmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
	"github.com/aplane-algo/aplane/internal/tealtemplate"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/internal/witness"
)

// The generation-side vocabulary is defined in terms of hostmeta, the
// durable storage vocabulary, so the two cannot drift: a contract revision
// edits hostmeta once and both sides follow at compile time.
const (
	// BoundedContract is the bounded-authorization contract.
	BoundedContract = hostmeta.BoundedContract
	// PlainContract is the plain host: signatures and overlays, no host rules.
	PlainContract = hostmeta.PlainContract
	// CosignerPublicKeyParameter is injected for cosigner-enabled profiles.
	CosignerPublicKeyParameter = hostmeta.CosignerPublicKeyParameter
	// RekeyToParameter carries a rekey-to list's entries. The framework
	// injects it for a profile with a list; a template that declares it must
	// match the injected definition exactly.
	RekeyToParameter = hostmeta.RekeyListEntriesParameter
	// RekeyOnlyThese is the template's rekey value for a rekey-to list:
	// rekey: refused, plus the list.
	RekeyOnlyThese = hostmeta.RekeyOnlyThese
	// RekeyPlusCosigned is the template's rekey value for a rekey-to list
	// beside cosigned rekeys: rekey: spending_key, plus the list, with a cosigner.
	RekeyPlusCosigned = hostmeta.RekeyPlusCosigned

	boundedReservedNamePrefix  = "bounded_"
	boundedReservedLabelPrefix = "__aplane_bounded1_"

	boundedProfileDomain              = "APLANE_BOUNDED_PROFILE_V2"
	boundedBehaviorParametersDomainV1 = "APLANE_BOUNDED_BEHAVIOR_PARAMETERS_V1"
)

// HostProfile defines the bounded envelope compiled around
// a composed DSA spending policy. Under the plain contract there is no
// envelope: no spend effects and no fee ceiling, only the rekey dispatch and
// the overlays.
type HostProfile struct {
	Contract string
	// Bounds is the bounded host's envelope, nil on a plain host.
	Bounds *ProfileBounds
	Rekey  hostmeta.RekeySetting
	// RekeyList is the template-level rekey-to list record; the root is filled
	// in at generation.
	RekeyList *hostmeta.RekeyList
	Cosigner  *hostmeta.CosignerAuthorization
}

// ProfileBounds is the envelope a bounded host compiles: the transaction kinds
// it may spend and its fee ceiling. The Layer 3 policy that completes the
// stored bounds is the composer's own setting.
type ProfileBounds struct {
	SpendEffects []txeffects.SpendEffect
	MaxFee       *uint64
}

func (bounds *ProfileBounds) spendEffectNames() []string {
	names := make([]string, len(bounds.SpendEffects))
	for i, effect := range bounds.SpendEffects {
		names[i] = string(effect)
	}
	return names
}

type hostFingerprint struct {
	CanonicalProfileHex string `json:"canonical_profile_hex"`
}

func cloneHostProfile(profile *HostProfile) *HostProfile {
	if profile == nil {
		return nil
	}
	cloned := *profile
	if profile.Bounds != nil {
		cloned.Bounds = &ProfileBounds{
			SpendEffects: append([]txeffects.SpendEffect(nil), profile.Bounds.SpendEffects...),
			MaxFee:       hostmeta.CloneMaxFee(profile.Bounds.MaxFee),
		}
	}
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

// validate delegates the bounded rule set to hostmeta, so generation and
// storage validation cannot diverge.
func (profile *HostProfile) validate() error {
	if profile == nil {
		return nil
	}
	if err := hostmeta.CheckBounds(profile.Contract, profile.Bounds != nil); err != nil {
		return err
	}
	if bounds := profile.Bounds; bounds != nil {
		if err := hostmeta.ValidateMaxFee(bounds.MaxFee); err != nil {
			return err
		}
		if err := hostmeta.ValidateSpendEffects(bounds.spendEffectNames()); err != nil {
			return err
		}
	}
	if err := hostmeta.ValidateRekeySetting(profile.Rekey); err != nil {
		return err
	}
	// Plus cosigned needs the cosigner: alone, the spending key already rekeys
	// anywhere, so the list would add nothing.
	if profile.RekeyList != nil && profile.Rekey == hostmeta.RekeySpendingKey && profile.Cosigner == nil {
		return fmt.Errorf("a rekey-to list beside a spending-key rekey (%s) needs a cosigner", hostmeta.RekeyPlusCosigned)
	}
	if err := hostmeta.ValidateCosignerAuthorizationProfile(profile.Cosigner, profile.Rekey); err != nil {
		return err
	}
	return nil
}

// validatedHostProfile canonicalizes a profile and checks it against its
// metadata, which catches contradictions such as a rekey-to list beside a
// spending-key rekey without a cosigner. CanonicalBoundedProfile encodes the
// result.
func validatedHostProfile(profile *HostProfile, metadata *hostmeta.Metadata) (*HostProfile, error) {
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

func canonicalBoundedProfile(profile *HostProfile) (*HostProfile, error) {
	if profile == nil {
		return nil, nil
	}
	if err := profile.validate(); err != nil {
		return nil, err
	}
	canonical := cloneHostProfile(profile)
	if canonical.Bounds != nil {
		canonical.Bounds.SpendEffects = canonicalSpendEffects(canonical.Bounds.SpendEffects)
	}
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

func hostFingerprintProjection(profile *HostProfile, metadata *hostmeta.Metadata) any {
	if profile == nil {
		return nil
	}
	encoded, err := CanonicalBoundedProfile(profile, metadata)
	if err != nil {
		return map[string]string{"invalid": err.Error()}
	}
	return hostFingerprint{CanonicalProfileHex: hex.EncodeToString(encoded)}
}

// CanonicalBoundedProfile encodes a profile using the bounded binary contract,
// which template fingerprints and the plain hosts' boundary digest hash.
func CanonicalBoundedProfile(profile *HostProfile, metadata *hostmeta.Metadata) ([]byte, error) {
	canonical, err := validatedHostProfile(profile, metadata)
	if err != nil {
		return nil, err
	}
	var encoded []byte
	encoded = hostmeta.AppendField(encoded, []byte(boundedProfileDomain))
	encoded = hostmeta.AppendField(encoded, []byte(canonical.Contract))
	// A plain host has no bounds, and its encoding says so as it always has:
	// no spend effects and no fee field. The contract name leads the encoding,
	// so the missing field needs no placeholder.
	var spendEffects []txeffects.SpendEffect
	var maxFee *uint64
	if canonical.Bounds != nil {
		spendEffects, maxFee = canonical.Bounds.SpendEffects, canonical.Bounds.MaxFee
	}
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(spendEffects)))
	for _, effect := range spendEffects {
		encoded = hostmeta.AppendField(encoded, []byte(effect))
	}
	if maxFee != nil {
		encoded = binary.BigEndian.AppendUint64(encoded, *maxFee)
	}
	encoded = hostmeta.AppendField(encoded, []byte(canonical.Rekey))
	// The list's contract and depth, never its root: the root is an instance
	// value, and the review digest binds the entries it comes from instead.
	if canonical.RekeyList == nil {
		encoded = binary.BigEndian.AppendUint32(encoded, 0)
	} else {
		encoded = binary.BigEndian.AppendUint32(encoded, 1)
		encoded = hostmeta.AppendField(encoded, []byte(canonical.RekeyList.Contract))
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(canonical.RekeyList.Depth))
	}
	if canonical.Cosigner == nil {
		encoded = binary.BigEndian.AppendUint32(encoded, 0)
	} else {
		encoded = binary.BigEndian.AppendUint32(encoded, 1)
		encoded = hostmeta.AppendField(encoded, []byte(canonical.Cosigner.Contract))
		encoded = hostmeta.AppendField(encoded, []byte(canonical.Cosigner.ComponentKeyType))
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(canonical.Cosigner.SignatureMaxSize))
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(canonical.Cosigner.RequiredOn)))
		for _, path := range canonical.Cosigner.RequiredOn {
			encoded = hostmeta.AppendField(encoded, []byte(path))
		}
	}
	encoded = hostmeta.AppendField(encoded, []byte(metadata.Layer3Policy()))
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(metadata.BaseSignatureArgLayout.Count))
	for _, maxSize := range metadata.BaseSignatureArgLayout.MaxSizes {
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(maxSize))
	}
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(metadata.DerivedArgs)))
	for _, arg := range metadata.DerivedArgs {
		encoded = hostmeta.AppendField(encoded, []byte(arg.Name))
		encoded = hostmeta.AppendField(encoded, []byte(arg.Kind))
		encoded = hostmeta.AppendField(encoded, []byte(arg.Parameter))
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(arg.MaxSize))
	}
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(metadata.RuntimeArgs)))
	for _, arg := range metadata.RuntimeArgs {
		encoded = hostmeta.AppendField(encoded, []byte(arg.Name))
		encoded = hostmeta.AppendField(encoded, []byte(arg.Type))
		if arg.Required {
			encoded = binary.BigEndian.AppendUint32(encoded, 1)
		} else {
			encoded = binary.BigEndian.AppendUint32(encoded, 0)
		}
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(arg.ByteLength))
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(arg.MaxSize))
	}
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(metadata.ArgumentLayout)))
	for _, slot := range metadata.ArgumentLayout {
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(slot.Index))
		encoded = hostmeta.AppendField(encoded, []byte(slot.Name))
		encoded = hostmeta.AppendField(encoded, []byte(slot.Source))
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(slot.MaxSize))
		encoded = hostmeta.AppendField(encoded, []byte(slot.Paths.Spend))
		encoded = hostmeta.AppendField(encoded, []byte(slot.Paths.SpendingRekey))
		encoded = hostmeta.AppendField(encoded, []byte(slot.Paths.ListedRekey))
	}
	return encoded, nil
}

func validateCanonicalMetadata(profile *HostProfile, metadata *hostmeta.Metadata) error {
	if err := metadata.ValidateProfile(); err != nil {
		return fmt.Errorf("invalid bounded profile metadata: %w", err)
	}
	if metadata.Contract != profile.Contract || !equalBoundsProfile(metadata.Bounds, profile.Bounds) ||
		metadata.Rekey != profile.Rekey ||
		!equalCosignerProfile(metadata.Cosigner, profile.Cosigner) || !equalRekeyListProfile(metadata.RekeyList, profile.RekeyList) {
		return fmt.Errorf("bounded profile metadata does not match the authorization profile")
	}
	return nil
}

// equalBoundsProfile compares the envelope; the Layer 3 policy is the
// metadata's alone.
func equalBoundsProfile(metadata *hostmeta.Bounds, profile *ProfileBounds) bool {
	if metadata == nil || profile == nil {
		return metadata == nil && profile == nil
	}
	return hostmeta.EqualMaxFee(metadata.MaxFee, profile.MaxFee) &&
		slices.Equal(metadata.SpendEffects, profile.spendEffectNames())
}

// equalRekeyListProfile compares the list's definition; the root is the
// instance's and only the metadata has it.
func equalRekeyListProfile(a, b *hostmeta.RekeyList) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Contract == b.Contract && a.Depth == b.Depth
}

func equalCosignerProfile(a, b *hostmeta.CosignerAuthorization) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Contract == b.Contract && a.ComponentKeyType == b.ComponentKeyType &&
		a.SignatureMaxSize == b.SignatureMaxSize && slices.Equal(a.RequiredOn, b.RequiredOn)
}

// CosignerParameterDef returns the definition of the cosigner key the
// composer injects for a cosigner of componentKeyType, which a provider that
// presents the key itself also uses. Its length is part of the composed
// fingerprint.
func CosignerParameterDef(componentKeyType string) lsigprovider.ParameterDef {
	def := lsigprovider.ParameterDef{
		Name:        CosignerPublicKeyParameter,
		Label:       "Cosigner Public Key",
		Description: "Falcon-1024 public key for bounded spend authorization",
		Type:        "bytes",
		Required:    true,
		MaxLength:   hostmeta.DefaultCosignerPublicKeySize * 2,
	}
	if publicKeySize, _, ok := hostmeta.CosignerSizes(componentKeyType); ok {
		def.MaxLength = publicKeySize * 2
	}
	if name, ok := witness.AlgorithmName(componentKeyType); ok {
		def.Description = name + " public key for bounded spend authorization"
	}
	return def
}

// cosignerPublicKeySize is the size of this composer's cosigner public key.
func (c *ComposedDSA) cosignerPublicKeySize() (int, error) {
	if c.host == nil || c.host.Cosigner == nil {
		return 0, fmt.Errorf("composer declares no bounded cosigner")
	}
	publicKeySize, _, ok := hostmeta.CosignerSizes(c.host.Cosigner.ComponentKeyType)
	if !ok {
		return 0, fmt.Errorf("unsupported bounded cosigner component key type %q", c.host.Cosigner.ComponentKeyType)
	}
	return publicKeySize, nil
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

func (c *ComposedDSA) validatedSignatureArgLayout() (SignatureArgLayout, error) {
	layout, ok := c.SignatureArgLayout()
	if !ok {
		return SignatureArgLayout{}, fmt.Errorf("base key type %q does not expose a static bounded signature argument layout", c.baseKeyType)
	}
	if err := hostmeta.ValidateSignatureLayout(layout); err != nil {
		return SignatureArgLayout{}, err
	}
	return layout, nil
}

// HostMetadata returns the canonical template-level inventory
// projection. Instance-only fields are populated during key generation.
func (c *ComposedDSA) HostMetadata() *hostmeta.Metadata {
	metadata, err := c.hostMetadataBase()
	if err != nil {
		return nil
	}
	return metadata
}

// BuildHostMetadata snapshots the complete non-secret bounded
// signing contract after program derivation. Existing keys use this durable
// projection and never need the installed YAML template to route or assemble.
func (c *ComposedDSA) BuildHostMetadata(publicKey []byte, params map[string]string, bytecode []byte) (*hostmeta.Metadata, error) {
	metadata, err := c.hostMetadataBase()
	if err != nil || metadata == nil {
		return metadata, err
	}
	profile := c.host
	if profile.Cosigner != nil {
		cosignerPublicKey, err := c.validatedCosignerPublicKey(publicKey, params)
		if err != nil {
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
	// Checked at generation, not on load: see ValidateNetworkLimits.
	if err := metadata.ValidateNetworkLimits(); err != nil {
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
	publicKeySize, err := c.cosignerPublicKeySize()
	if err != nil {
		return nil, err
	}
	cosignerPublicKey, err := decodeHexParameter(params[CosignerPublicKeyParameter], CosignerPublicKeyParameter, publicKeySize)
	if err != nil {
		return nil, err
	}
	if err := c.refuseSharedSpendingKey("cosigner", spendingPublicKey, c.host.Cosigner.ComponentKeyType, cosignerPublicKey); err != nil {
		return nil, err
	}
	return cosignerPublicKey, nil
}

func (c *ComposedDSA) hostMetadataBase() (*hostmeta.Metadata, error) {
	profile, layout, err := c.validateHostConfig()
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, nil
	}
	metadata := &hostmeta.Metadata{
		Contract: profile.Contract,
		BaseSignatureArgLayout: hostmeta.SignatureArgLayout{
			Count:    layout.Count,
			MaxSizes: append([]int(nil), layout.MaxSizes...),
		},
		RuntimeArgs: append([]hostmeta.RuntimeArg(nil), c.hostRuntimeArgs...),
		DerivedArgs: append([]hostmeta.DerivedArg(nil), c.derivedArgs...),
	}
	if profile.Bounds != nil {
		metadata.Bounds = &hostmeta.Bounds{
			SpendEffects: profile.Bounds.spendEffectNames(),
			MaxFee:       hostmeta.CloneMaxFee(profile.Bounds.MaxFee),
			Layer3Policy: c.Layer3PolicyName(),
		}
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
	metadata.Rekey = profile.Rekey
	metadata.ArgumentLayout = hostArgumentLayout(layout, profile, metadata.DerivedArgs, metadata.RuntimeArgs)
	return metadata, nil
}

func hostArgumentLayout(layout SignatureArgLayout, profile *HostProfile, derived []hostmeta.DerivedArg, runtime []hostmeta.RuntimeArg) []hostmeta.ArgumentSlot {
	slots := make([]hostmeta.ArgumentSlot, 0, layout.Count+len(derived)+len(runtime)+2)
	for i, maxSize := range layout.MaxSizes {
		slots = append(slots, hostmeta.ArgumentSlot{
			Index: i, Name: fmt.Sprintf("base_signature_%d", i), Source: hostmeta.ArgSourceBaseSignature, MaxSize: maxSize,
			Paths: hostmeta.ArgumentPathMask{Spend: hostmeta.ArgRequired, SpendingRekey: hostmeta.ArgRequired, ListedRekey: hostmeta.ArgRequired},
		})
	}
	for _, arg := range derived {
		// A recipient proof serves Layer 3, which no rekey reaches; a list proof
		// serves the listed rekey alone.
		paths := hostmeta.ArgumentPathMask{Spend: hostmeta.ArgOptional, SpendingRekey: hostmeta.ArgForbidden, ListedRekey: hostmeta.ArgForbidden}
		if arg.Kind == hostmeta.DerivedArgRekeyListProof {
			paths = hostmeta.ArgumentPathMask{Spend: hostmeta.ArgForbidden, SpendingRekey: hostmeta.ArgForbidden, ListedRekey: hostmeta.ArgRequired}
		}
		slots = append(slots, hostmeta.ArgumentSlot{
			Index: len(slots), Name: arg.Name, Source: hostmeta.ArgSourceDerived, MaxSize: arg.MaxSize, Paths: paths,
		})
	}
	// A rekey never reaches Layer 3, so its arguments are spend-only.
	for _, arg := range runtime {
		slots = append(slots, hostmeta.ArgumentSlot{
			Index: len(slots), Name: arg.Name, Source: hostmeta.ArgSourceRuntime, MaxSize: arg.MaxSize,
			Paths: hostmeta.ArgumentPathMask{Spend: hostmeta.ArgRequired, SpendingRekey: hostmeta.ArgForbidden, ListedRekey: hostmeta.ArgForbidden},
		})
	}
	if profile.Cosigner != nil {
		slots = append(slots, hostmeta.ArgumentSlot{
			Index: len(slots), Name: hostmeta.CosignerSignatureSlot, Source: hostmeta.ArgSourceCosigner,
			MaxSize: profile.Cosigner.SignatureMaxSize,
			Paths:   hostmeta.CosignerSlotPaths(profile.Cosigner),
		})
	}
	return slots
}

func (c *ComposedDSA) validateHostConfig() (*HostProfile, SignatureArgLayout, error) {
	profile, err := canonicalBoundedProfile(c.host)
	if err != nil {
		return nil, SignatureArgLayout{}, err
	}
	if profile == nil {
		return nil, SignatureArgLayout{}, nil
	}
	switch {
	case profile.Bounds == nil:
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
	if err := validateHostReservedNames(profile, c.params, c.runtimeArgs, c.derivedArgs, c.templateVars, c.tealSuffix); err != nil {
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
		return hostmeta.Layer3PolicyCustom
	}
	return hostmeta.StoredLayer3Policy(policy.Policy, hasAuthorTEAL)
}

func validateHostReservedNames(profile *HostProfile, params []lsigprovider.ParameterDef, runtimeArgs []lsigprovider.RuntimeArgDef, derivedArgs []hostmeta.DerivedArg, templateVars []tealtemplate.TemplateVariable, teal string) error {
	for _, param := range params {
		if isCosignerReservedName(param.Name) {
			if param.Name != CosignerPublicKeyParameter || profile.Cosigner == nil {
				return fmt.Errorf("parameter name %q uses reserved cosigner namespace", param.Name)
			}
			want := CosignerParameterDef(profile.Cosigner.ComponentKeyType)
			if param.Type != want.Type || !param.Required || param.MaxLength != want.MaxLength {
				return fmt.Errorf("parameter %q does not match the framework-injected contract", param.Name)
			}
			continue
		}
		if param.Name == RekeyToParameter && profile.RekeyList != nil {
			want := rekeyListEntriesParameterDef(profile.Rekey)
			if param.Type != want.Type || !param.Required || param.MinItems != want.MinItems || param.MaxItems != want.MaxItems {
				return fmt.Errorf("parameter %q does not match the framework-injected contract", param.Name)
			}
			continue
		}
		if reason := reservedFrameworkName(param.Name); reason != "" {
			return fmt.Errorf("parameter name %q uses %s", param.Name, reason)
		}
	}
	for _, arg := range runtimeArgs {
		if isCosignerReservedName(arg.Name) {
			return fmt.Errorf("runtime arg name %q uses reserved cosigner namespace", arg.Name)
		}
		if reason := reservedFrameworkName(arg.Name); reason != "" {
			return fmt.Errorf("runtime arg name %q uses %s", arg.Name, reason)
		}
	}
	// The rekey-to list is private: the program commits only to its root, so no
	// author TEAL may read the entries, and no derived argument may prove one: a
	// recipient-tree proof is unsalted, so a spend would publish siblings anyone
	// can test guessed addresses against. The framework's own list proof is
	// salted and added after this check.
	listPrivate := func(name string) bool { return profile.RekeyList != nil && name == RekeyToParameter }
	for _, arg := range derivedArgs {
		if listPrivate(arg.Parameter) {
			return fmt.Errorf("derived argument %q would publish proofs over the private rekey-to list", arg.Name)
		}
	}
	for _, variable := range templateVars {
		if listPrivate(variable.Name) || listPrivate(variable.Parameter) {
			return fmt.Errorf("template variable %q would compile the private rekey-to list into the program", variable.Name)
		}
		if isCosignerReservedName(variable.Name) || isCosignerReservedName(variable.Parameter) {
			return fmt.Errorf("template variable %q uses reserved cosigner namespace", variable.Name)
		}
		if reason := reservedFrameworkName(variable.Name); reason != "" {
			return fmt.Errorf("template variable name %q uses %s", variable.Name, reason)
		}
		if reason := reservedFrameworkName(variable.Parameter); reason != "" {
			return fmt.Errorf("template variable %q references parameter %q, which uses %s", variable.Name, variable.Parameter, reason)
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
			// The delimiters a reference can sit in, list syntax included.
			name := strings.Trim(token, "{}.@")
			if reason := reservedFrameworkName(name); reason != "" {
				return fmt.Errorf("author TEAL identifier %q uses %s", token, reason)
			}
			if listPrivate(name) {
				return fmt.Errorf("author TEAL reads %q, which would compile the private rekey-to list into the program", token)
			}
		}
	}
	return nil
}

// reservedFrameworkName says why a template may not use name, or "" when it
// may. The bounded_ prefix is the framework's. So is the rekey-to list root,
// which key generation writes into an account's parameters and nothing else
// may set.
func reservedFrameworkName(name string) string {
	switch {
	case name == hostmeta.RekeyListRootParameter:
		return "the reserved rekey-to list root name"
	case strings.HasPrefix(name, boundedReservedNamePrefix):
		return "reserved bounded_ prefix"
	}
	return ""
}

func isCosignerReservedName(name string) bool {
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

// CanonicalBoundedBehaviorParameters encodes behavior-bearing creation values
// in parameter-definition order.
func CanonicalBoundedBehaviorParameters(params map[string]string, defs []lsigprovider.ParameterDef) ([]byte, error) {
	normalized, err := lsigprovider.NormalizeCreationParams(params, defs)
	if err != nil {
		return nil, fmt.Errorf("normalize behavior parameters: %w", err)
	}

	var encoded []byte
	encoded = hostmeta.AppendField(encoded, []byte(boundedBehaviorParametersDomainV1))
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(defs)))
	for _, def := range defs {
		value, present := normalized[def.Name]
		var canonical []byte
		if def.Required || (present && value != "") {
			canonical, err = canonicalParameterValue(def, value)
			if err != nil {
				return nil, fmt.Errorf("canonical parameter %s: %w", def.Name, err)
			}
		}
		encoded = hostmeta.AppendField(encoded, []byte(def.Name))
		encoded = hostmeta.AppendField(encoded, []byte(def.Type))
		encoded = hostmeta.AppendField(encoded, canonical)
	}
	return encoded, nil
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
		return binary.BigEndian.AppendUint64(nil, number), nil
	case "address[]":
		items := splitCanonicalList(value)
		encoded := binary.BigEndian.AppendUint32(nil, uint32(len(items)))
		for _, item := range items {
			address, err := types.DecodeAddress(item)
			if err != nil {
				return nil, err
			}
			encoded = hostmeta.AppendField(encoded, address[:])
		}
		return encoded, nil
	case "uint64[]":
		items := splitCanonicalList(value)
		encoded := binary.BigEndian.AppendUint32(nil, uint32(len(items)))
		for _, item := range items {
			number, err := strconv.ParseUint(item, 10, 64)
			if err != nil {
				return nil, err
			}
			encoded = hostmeta.AppendField(encoded, binary.BigEndian.AppendUint64(nil, number))
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
