// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package boundedmeta owns the durable, non-secret bounded-authorization
// metadata stored with a LogicSig key. It deliberately has no dependency on a
// runtime template or composer registration.
package boundedmeta

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aplane-algo/aplane/internal/rekeylist"
	"github.com/aplane-algo/aplane/internal/witness"
)

const (
	// Contract is the bounded account contract: the spending signature, a
	// transaction envelope (fee ceiling, rekey setting, admitted spend types)
	// and a Layer 3 policy. docs/ARCH_BOUNDED_DSA.md freezes it.
	Contract = "bounded2"
	// PlainContract is the plain host: the spending key and its overlays, with
	// no host rules. Every transaction that doesn't rekey is a spend, of any
	// type, closes and clawback included, and there is no fee ceiling. A
	// cosigner, when it has one, is the only restriction on what gets signed.
	PlainContract               = "plain1"
	Layer3PolicyCustom          = "custom"
	Layer3PolicyFixedAllowlist  = "fixed_allowlist"
	Layer3PolicyMerkleAllowlist = "merkle_allowlist"
	// The *Custom values record a framework allowlist followed by author TEAL.
	// Plain "custom" would hide that the allowlist is framework-enforced.
	Layer3PolicyFixedAllowlistCustom  = "fixed_allowlist_custom"
	Layer3PolicyMerkleAllowlistCustom = "merkle_allowlist_custom"
	SpendEffectPay                    = "pay"
	SpendEffectAxfer                  = "axfer"
	SpendEffectAssetOptIn             = "asset_opt_in"
	CosignerContractV1                = "cosigner1"
	CosignerPublicKeyParameter        = "cosigner_public_key"
	// CosignerKeyTypeParameter records a plain host account's cosigner key
	// type when it is not DefaultCosignerComponentKeyType. The signer fills it
	// from the cosigner reference; an account without it has the default.
	CosignerKeyTypeParameter = "cosigner_key_type"
	CosignerSignatureSlot    = "cosigner_signature"
	// DefaultCosignerComponentKeyType is the cosigner key type of an account
	// that records none: a plain host account with a Falcon-1024 cosigner, and
	// every composed template's. Its sizes follow.
	DefaultCosignerComponentKeyType = witness.Falcon1024V1
	DefaultCosignerPublicKeySize    = witness.Falcon1024PublicKeySize
	DefaultCosignerSignatureMaxSize = witness.Falcon1024SignatureSize
	// MaxFeeLimit is the largest fee ceiling an account may record. It is not a
	// budget: it is the largest whole number every client reads exactly, since
	// the ceiling travels as a JSON number.
	MaxFeeLimit uint64 = 1<<53 - 1
)

// Layer3PolicyNone compiles no Layer 3: the envelope's transfer kinds and fee
// ceiling, and the spending signature, are the whole spending rule. It reads no
// parameter and takes no author TEAL.
const Layer3PolicyNone = "none"

// layer3Traits is what a stored Layer 3 policy name says about the program.
type layer3Traits struct {
	inlineList bool // the framework inline recipient check runs
	merkleList bool // the framework Merkle recipient check runs
	authorTEAL bool // author TEAL runs, alone or after the framework's check
}

// layer3Policies is the closed stored vocabulary and the one place that says
// what each name means. The predicates below, the vocabulary check, the
// argument rules and the _custom derivation all read it, so a new name is
// added here and nowhere else.
var layer3Policies = map[string]layer3Traits{
	Layer3PolicyNone:                  {},
	Layer3PolicyCustom:                {authorTEAL: true},
	Layer3PolicyFixedAllowlist:        {inlineList: true},
	Layer3PolicyMerkleAllowlist:       {merkleList: true},
	Layer3PolicyFixedAllowlistCustom:  {inlineList: true, authorTEAL: true},
	Layer3PolicyMerkleAllowlistCustom: {merkleList: true, authorTEAL: true},
}

// IsKnownLayer3Policy reports whether policy is in the stored vocabulary.
func IsKnownLayer3Policy(policy string) bool {
	_, ok := layer3Policies[policy]
	return ok
}

// IsMerkleListPolicy reports whether a Layer 3 policy proves its recipient by
// a Merkle proof.
func IsMerkleListPolicy(policy string) bool { return layer3Policies[policy].merkleList }

// IsCustomPolicy reports whether author TEAL runs in Layer 3, alone or after
// a framework allowlist.
func IsCustomPolicy(policy string) bool { return layer3Policies[policy].authorTEAL }

// IsRecipientListPolicy reports whether a Layer 3 policy limits spending to a
// framework-enforced recipient list, alone or followed by author TEAL. A
// policy it does not know is not a list.
func IsRecipientListPolicy(policy string) bool {
	traits := layer3Policies[policy]
	return traits.inlineList || traits.merkleList
}

// StoredLayer3Policy is the name stored for a framework policy: the policy
// itself, or its _custom form when author TEAL follows it. A framework policy
// with no _custom form is returned unchanged.
func StoredLayer3Policy(framework string, hasAuthorTEAL bool) string {
	if !hasAuthorTEAL {
		return framework
	}
	if custom := framework + "_custom"; layer3Policies[custom].authorTEAL {
		return custom
	}
	return framework
}

// SignatureArgLayout is the durable maximum shape of the spending signature
// args emitted before any Layer-3 or cosigner args.
type SignatureArgLayout struct {
	Count    int   `json:"count"`
	MaxSizes []int `json:"max_sizes"`
}

// RuntimeArg is the durable Layer-3 runtime-argument definition. Its slot and
// path requirements are frozen separately in ArgumentLayout.
type RuntimeArg struct {
	Name        string `json:"name"`
	Label       string `json:"label,omitempty"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type"`
	Required    bool   `json:"required,omitempty"`
	ByteLength  int    `json:"byte_length,omitempty"`
	MaxSize     int    `json:"max_size"`
}

// CosignerAuthorization is the durable cosigner spend-authorization contract for
// one bounded key. PublicKeyHex and ComponentKeyID are instance fields filled
// during key generation; the remaining fields are present in template-level
// inventory metadata as well.
type CosignerAuthorization struct {
	Contract         string   `json:"contract"`
	ComponentKeyType string   `json:"component_key_type"`
	PublicKeyHex     string   `json:"public_key,omitempty"`
	ComponentKeyID   string   `json:"component_key_id,omitempty"`
	SignatureMaxSize int      `json:"signature_max_size"`
	RequiredOn       []string `json:"required_on"`
}

// RekeyOnlyThese names "only these addresses" where an account is declared: a
// template's rekey value, and the general type's rekey authority. It is
// rekey: refused plus a rekey-to list, and stored that way.
const RekeyOnlyThese = "only_these"

// RekeyPlusCosigned names "these addresses, plus others with the cosigner": a
// listed target takes the spending key alone, any other the spending key and the
// cosigner. It is rekey: spending_key plus a rekey-to list on a cosigned account,
// and stored that way.
const RekeyPlusCosigned = "plus_cosigned"

// RekeyListContractV1 identifies the rekey-to list overlay's contract: the
// hiding tree in internal/rekeylist at its fixed depth.
const RekeyListContractV1 = "rekey_list1"

// Creation parameters of a rekey-to list. The framework injects the entries
// parameter, which the general bounded type also takes by the same name, so a
// stored account's parameters hold its entries under the name its list proof
// reads. The generator fills in the root, which it computes from the entries
// and a seed derived from the spending key; that name is reserved.
const (
	RekeyListEntriesParameter = "rekey_to"
	RekeyListRootParameter    = "rekey_to_root"
)

// RekeyList is the rekey-to list overlay: with it, a rekey may go to a listed
// address with the spending key alone. Under rekey: refused it is "only these":
// every other rekey is refused. RootHex is an instance field filled during key
// generation; the rest is template-level.
type RekeyList struct {
	Contract string `json:"contract"`
	Depth    int    `json:"depth"`
	RootHex  string `json:"root,omitempty"`
}

// Bounds is what a bounded host adds to a host account: the transaction kinds
// it may spend, a fee ceiling, and a Layer 3 policy. They come together or not
// at all, so a plain host's metadata carries no Bounds rather than empty ones.
type Bounds struct {
	SpendEffects []string `json:"spend_effects"`
	// MaxFee is the fee ceiling. It is a pointer so that a stored object
	// without one is refused rather than read as a ceiling of zero.
	MaxFee       *uint64 `json:"max_fee"`
	Layer3Policy string  `json:"layer3_policy"`
}

// Metadata is the complete non-secret signing contract for one host account.
type Metadata struct {
	Contract               string                 `json:"contract"`
	BaseSignatureArgLayout SignatureArgLayout     `json:"base_signature_arg_layout"`
	Rekey                  RekeySetting           `json:"rekey"`
	Cosigner               *CosignerAuthorization `json:"cosigner,omitempty"`
	RekeyList              *RekeyList             `json:"rekey_list,omitempty"`
	RuntimeArgs            []RuntimeArg           `json:"runtime_args"`
	DerivedArgs            []DerivedArg           `json:"derived_args"`
	ArgumentLayout         []ArgumentSlot         `json:"argument_layout"`
	// Bounds is set on a bounded host and nil on a plain one; CheckBounds
	// holds the two together.
	Bounds *Bounds `json:"bounds,omitempty"`
}

// cloneBounds returns a deep copy of bounds, with a nil spend-effect list made
// empty as Clone makes every list.
func cloneBounds(bounds *Bounds) *Bounds {
	if bounds == nil {
		return nil
	}
	cloned := Bounds{
		SpendEffects: slices.Clone(bounds.SpendEffects),
		MaxFee:       CloneMaxFee(bounds.MaxFee),
		Layer3Policy: bounds.Layer3Policy,
	}
	if cloned.SpendEffects == nil {
		cloned.SpendEffects = []string{}
	}
	return &cloned
}

func equalBounds(a, b *Bounds) bool {
	if a == nil || b == nil {
		return a == b
	}
	return slices.Equal(a.SpendEffects, b.SpendEffects) &&
		EqualMaxFee(a.MaxFee, b.MaxFee) &&
		a.Layer3Policy == b.Layer3Policy
}

// CheckBounds refuses a contract this package doesn't know, and bounds that
// don't belong to the contract: the bounded host has them and the plain host
// doesn't. It is the one place that ties a contract to having bounds.
func CheckBounds(contract string, hasBounds bool) error {
	switch contract {
	case Contract:
		if !hasBounds {
			return fmt.Errorf("%s requires bounds", Contract)
		}
	case PlainContract:
		if hasBounds {
			return fmt.Errorf("%s has no host rules: bounds must be absent", PlainContract)
		}
	default:
		return fmt.Errorf("unsupported bounded authorization contract %q", contract)
	}
	return nil
}

// FeeCeiling is the account's fee ceiling, or nil when it has none: a host
// without bounds. The caller must not change the value it points to.
func (metadata *Metadata) FeeCeiling() *uint64 {
	if metadata == nil || metadata.Bounds == nil {
		return nil
	}
	return metadata.Bounds.MaxFee
}

// Layer3Policy is the account's Layer 3 policy: its bounds', or none for a
// host without bounds, which compiles no Layer 3.
func (metadata *Metadata) Layer3Policy() string {
	if metadata == nil || metadata.Bounds == nil {
		return Layer3PolicyNone
	}
	return metadata.Bounds.Layer3Policy
}

// Clone returns a deep copy suitable for crossing cache and API boundaries.
func Clone(metadata *Metadata) *Metadata {
	if metadata == nil {
		return nil
	}
	cloned := *metadata
	cloned.Bounds = cloneBounds(metadata.Bounds)
	cloned.BaseSignatureArgLayout.MaxSizes = slices.Clone(metadata.BaseSignatureArgLayout.MaxSizes)
	if metadata.Cosigner != nil {
		cosigner := *metadata.Cosigner
		cosigner.RequiredOn = slices.Clone(metadata.Cosigner.RequiredOn)
		cloned.Cosigner = &cosigner
	}
	if metadata.RekeyList != nil {
		list := *metadata.RekeyList
		cloned.RekeyList = &list
	}
	cloned.RuntimeArgs = slices.Clone(metadata.RuntimeArgs)
	cloned.DerivedArgs = slices.Clone(metadata.DerivedArgs)
	cloned.ArgumentLayout = slices.Clone(metadata.ArgumentLayout)
	if cloned.BaseSignatureArgLayout.MaxSizes == nil {
		cloned.BaseSignatureArgLayout.MaxSizes = []int{}
	}
	if cloned.RuntimeArgs == nil {
		cloned.RuntimeArgs = []RuntimeArg{}
	}
	if cloned.DerivedArgs == nil {
		cloned.DerivedArgs = []DerivedArg{}
	}
	if cloned.ArgumentLayout == nil {
		cloned.ArgumentLayout = []ArgumentSlot{}
	}
	return &cloned
}

// Equal reports whether two metadata records describe the same frozen signing
// contract, field for field. nil slices compare equal to empty ones so
// JSON-decoded and Clone-normalized records agree.
func (metadata *Metadata) Equal(other *Metadata) bool {
	if metadata == nil || other == nil {
		return metadata == other
	}
	return metadata.Contract == other.Contract &&
		metadata.BaseSignatureArgLayout.Count == other.BaseSignatureArgLayout.Count &&
		slices.Equal(metadata.BaseSignatureArgLayout.MaxSizes, other.BaseSignatureArgLayout.MaxSizes) &&
		equalBounds(metadata.Bounds, other.Bounds) &&
		metadata.Rekey == other.Rekey &&
		equalCosignerAuthorization(metadata.Cosigner, other.Cosigner) &&
		equalRekeyList(metadata.RekeyList, other.RekeyList) &&
		slices.Equal(metadata.RuntimeArgs, other.RuntimeArgs) &&
		slices.Equal(metadata.DerivedArgs, other.DerivedArgs) &&
		slices.Equal(metadata.ArgumentLayout, other.ArgumentLayout)
}

// Validate checks the durable bounded vocabulary without consulting an
// installed provider or template.
func (metadata *Metadata) Validate() error {
	if err := metadata.ValidateProfile(); err != nil {
		return err
	}
	if err := validateCosignerMetadata(metadata.Cosigner); err != nil {
		return err
	}
	// The signer compares the list it rebuilds with this root before every
	// listed rekey, so a stored list without one is corrupt.
	if metadata.RekeyList != nil {
		if _, err := DecodeCanonicalHex("rekey-to list root", metadata.RekeyList.RootHex, 32, 32); err != nil {
			return err
		}
	}
	return nil
}

// ValidateProfile checks the template-level bounded contract fields. Instance
// fields such as the cosigner key are validated only by Validate after key
// generation.
func (metadata *Metadata) ValidateProfile() error {
	if metadata == nil {
		return fmt.Errorf("bounded authorization metadata is nil")
	}
	if err := CheckBounds(metadata.Contract, metadata.Bounds != nil); err != nil {
		return err
	}
	if metadata.Bounds != nil {
		if err := metadata.Bounds.validate(); err != nil {
			return err
		}
	}
	if err := ValidateRekeySetting(metadata.Rekey); err != nil {
		return err
	}
	if err := ValidateCosignerAuthorizationProfile(metadata.Cosigner, metadata.Rekey); err != nil {
		return err
	}
	if err := metadata.ValidateRekeyList(); err != nil {
		return err
	}
	// Durable validation checks structure only. Whether a combination is wise
	// (a refused account that can't send what it holds, for one) is the
	// user's choice; a check for it
	// belongs at generation, never here, so accounts created without it keep
	// loading.
	if err := ValidateSignatureLayout(metadata.BaseSignatureArgLayout); err != nil {
		return err
	}
	if err := validateArgumentLayout(metadata); err != nil {
		return err
	}
	// Layer 3 reads recipient proofs; a rekey-list proof serves the rekey path.
	// A host without bounds has no Layer 3, so it is held to the rules of none.
	layer3 := metadata.Layer3Policy()
	recipientProofs := 0
	for _, arg := range metadata.DerivedArgs {
		if arg.Kind == DerivedArgMerkleProof {
			recipientProofs++
		}
	}
	// A Merkle list takes exactly one recipient proof. Author TEAL with no
	// framework policy may declare its own; every other known policy takes none.
	switch {
	case IsMerkleListPolicy(layer3):
		if recipientProofs != 1 {
			return fmt.Errorf("%s requires exactly one derived Merkle proof argument", layer3)
		}
	case layer3 != Layer3PolicyCustom:
		if recipientProofs != 0 {
			return fmt.Errorf("%s must not declare derived arguments", layer3)
		}
	}
	// "none" has nothing that could read a runtime argument.
	if layer3 == Layer3PolicyNone && len(metadata.RuntimeArgs) != 0 {
		return fmt.Errorf("%s must not declare runtime arguments", layer3)
	}
	return nil
}

// validate checks a bounded host's own rules: a fee ceiling the wire can
// carry, a known Layer 3 policy, and at least one spend effect.
func (bounds *Bounds) validate() error {
	if err := ValidateMaxFee(bounds.MaxFee); err != nil {
		return err
	}
	if !IsKnownLayer3Policy(bounds.Layer3Policy) {
		return fmt.Errorf("unsupported %s layer3_policy %q", Contract, bounds.Layer3Policy)
	}
	return ValidateSpendEffects(bounds.SpendEffects)
}

// ValidateMaxFee checks a bounded host's fee ceiling: it has one, and it is no
// larger than the wire can carry. Storage, generation and the classifier all
// use this one check, so bounds without a ceiling are refused everywhere and
// never read as a ceiling of zero or as none.
func ValidateMaxFee(fee *uint64) error {
	if fee == nil {
		return fmt.Errorf("%s requires max_fee", Contract)
	}
	if *fee > MaxFeeLimit {
		return fmt.Errorf("max_fee %d is above %d, the largest value every client reads exactly", *fee, MaxFeeLimit)
	}
	return nil
}

// CloneMaxFee copies a fee ceiling, so a projection never shares the stored one.
func CloneMaxFee(fee *uint64) *uint64 {
	if fee == nil {
		return nil
	}
	return new(*fee)
}

// EqualMaxFee reports whether two fee ceilings are the same: both absent, or
// both present and equal.
func EqualMaxFee(a, b *uint64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func equalCosignerAuthorization(a, b *CosignerAuthorization) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Contract == b.Contract &&
		a.ComponentKeyType == b.ComponentKeyType &&
		a.PublicKeyHex == b.PublicKeyHex &&
		a.ComponentKeyID == b.ComponentKeyID &&
		a.SignatureMaxSize == b.SignatureMaxSize &&
		slices.Equal(a.RequiredOn, b.RequiredOn)
}

// ValidateCosignerAuthorizationProfile checks definition-level cosigner fields
// against the account's rekey setting. Instance public-key fields are validated
// by Metadata.Validate after key generation.
func ValidateCosignerAuthorizationProfile(cosigner *CosignerAuthorization, rekey RekeySetting) error {
	if cosigner == nil {
		return nil
	}
	if cosigner.Contract != CosignerContractV1 {
		return fmt.Errorf("unsupported bounded cosigner contract %q", cosigner.Contract)
	}
	_, signatureMaxSize, ok := CosignerSizes(cosigner.ComponentKeyType)
	if !ok {
		return fmt.Errorf("unsupported bounded cosigner component key type %q", cosigner.ComponentKeyType)
	}
	if cosigner.SignatureMaxSize != signatureMaxSize {
		return fmt.Errorf("bounded cosigner signature_max_size %d invalid (expected %d)", cosigner.SignatureMaxSize, signatureMaxSize)
	}
	if want := CosignerRequiredOn(rekey); !slices.Equal(cosigner.RequiredOn, want) {
		return fmt.Errorf("bounded cosigner required_on must be exactly [%s] with rekey %s", strings.Join(want, ", "), rekey)
	}
	return nil
}

// CosignerRequiredOn is every path a cosigned account's cosigner signs: each
// spend, and each rekey the spending key may make, which needs the cosigner
// too. A listed rekey never asks the cosigner.
func CosignerRequiredOn(rekey RekeySetting) []string {
	if rekey == RekeySpendingKey {
		return []string{PathSpend, PathSpendingRekey}
	}
	return []string{PathSpend}
}

// CosignerSizes is a cosigner key type's public key size and largest
// signature, for each type an account can take as its cosigner.
func CosignerSizes(componentKeyType string) (publicKeySize, signatureMaxSize int, ok bool) {
	publicKeySize, publicOK := witness.PublicKeySize(componentKeyType)
	signatureMaxSize, signatureOK := witness.SignatureMaxSize(componentKeyType)
	if !publicOK || !signatureOK {
		return 0, 0, false
	}
	return publicKeySize, signatureMaxSize, true
}

func validateCosignerMetadata(cosigner *CosignerAuthorization) error {
	if cosigner == nil {
		return nil
	}
	publicKeySize, _, ok := CosignerSizes(cosigner.ComponentKeyType)
	if !ok {
		return fmt.Errorf("unsupported bounded cosigner component key type %q", cosigner.ComponentKeyType)
	}
	publicKey, err := DecodeCanonicalHex("cosigner public_key", cosigner.PublicKeyHex, publicKeySize, publicKeySize)
	if err != nil {
		return err
	}
	wantKeyID, err := witness.ID(cosigner.ComponentKeyType, publicKey)
	if err != nil {
		return err
	}
	if cosigner.ComponentKeyID != wantKeyID {
		return fmt.Errorf("cosigner component_key_id does not match public_key")
	}
	return nil
}

// ValidateSpendEffects enforces the bounded spend-effect rules: at
// least one entry, known effects only, no duplicates. Both storage and
// generation consume this single rule set.
func ValidateSpendEffects(spendEffects []string) error {
	if len(spendEffects) == 0 {
		return fmt.Errorf("a bounded account requires at least one spend effect")
	}
	seen := make(map[string]struct{}, len(spendEffects))
	for _, effect := range spendEffects {
		if effect != SpendEffectPay && effect != SpendEffectAxfer && effect != SpendEffectAssetOptIn {
			return fmt.Errorf("unsupported spend effect %q", effect)
		}
		if _, exists := seen[effect]; exists {
			return fmt.Errorf("duplicate spend effect %q", effect)
		}
		seen[effect] = struct{}{}
	}
	return nil
}

// ValidateRekeySetting accepts the rekey settings a bounded account may declare.
func ValidateRekeySetting(setting RekeySetting) error {
	switch setting {
	case RekeyRefused, RekeySpendingKey:
		return nil
	default:
		return fmt.Errorf("unsupported rekey setting %q", setting)
	}
}

// RefusesRekeys reports whether the account's rekey setting is refused: it has no
// rekey path, or, with a rekey-to list, only a pure rekey to a listed address.
func (metadata *Metadata) RefusesRekeys() bool {
	return metadata != nil && metadata.Rekey == RekeyRefused
}

// HasRecipientList reports whether Layer 3 limits spending to a recipient list.
func (metadata *Metadata) HasRecipientList() bool {
	return IsRecipientListPolicy(metadata.Layer3Policy())
}

// Contained reports whether the spending key alone can move value only to
// addresses the account lists: it refuses rekeys, or takes only listed ones, and
// Layer 3 holds a recipient list. A listed rekey hands the whole account to a
// listed address, whose key the boundary no longer binds. Fees are outside that:
// each is capped per transaction, but repeated transactions can still spend the
// balance on fees.
func (metadata *Metadata) Contained() bool {
	return metadata.RefusesRekeys() && metadata.HasRecipientList()
}

func ValidateSignatureLayout(layout SignatureArgLayout) error {
	if layout.Count <= 0 || len(layout.MaxSizes) != layout.Count {
		return fmt.Errorf("base_signature_arg_layout count %d does not match %d size bounds", layout.Count, len(layout.MaxSizes))
	}
	for i, size := range layout.MaxSizes {
		if size <= 0 {
			return fmt.Errorf("base signature arg %d maximum size must be positive", i)
		}
	}
	return nil
}

// DecodeCanonicalHex decodes a canonical hex field: non-empty, lowercase, no
// 0x prefix. The decoded byte length must lie within [minSize, maxSize];
// pass equal bounds for an exact size, or maxSize <= 0 to skip the length
// check. This is the single canonicality rule for bounded wire fields — the
// helper binary, the signer, and the key codec all decode through it, or
// through DecodeCanonicalHexBytes, its form for a value held as bytes.
func DecodeCanonicalHex(field, value string, minSize, maxSize int) ([]byte, error) {
	text := []byte(value)
	defer clear(text)
	return DecodeCanonicalHexBytes(field, text, minSize, maxSize)
}

// DecodeCanonicalHexBytes is DecodeCanonicalHex for a value held as bytes, so
// a secret need not become a string to be decoded. It only reads value, and
// returns a new buffer.
func DecodeCanonicalHexBytes(field string, value []byte, minSize, maxSize int) ([]byte, error) {
	if len(value) == 0 || !unchangedByToLower(value) {
		return nil, fmt.Errorf("%s must be non-empty lowercase hex", field)
	}
	decoded := make([]byte, hex.DecodedLen(len(value)))
	n, err := hex.Decode(decoded, value)
	if err != nil {
		clear(decoded)
		return nil, fmt.Errorf("invalid %s: %w", field, err)
	}
	decoded = decoded[:n]
	if maxSize > 0 && (len(decoded) < minSize || len(decoded) > maxSize) {
		clear(decoded)
		if minSize == maxSize {
			return nil, fmt.Errorf("%s length %d invalid (expected %d bytes)", field, len(decoded), maxSize)
		}
		return nil, fmt.Errorf("%s length %d invalid (expected %d-%d bytes)", field, len(decoded), minSize, maxSize)
	}
	return decoded, nil
}

// unchangedByToLower reports whether strings.ToLower would return value
// unchanged, without making the lowercase copy: every rune is valid UTF-8
// (ToLower replaces an invalid byte) and is its own lowercase.
func unchangedByToLower(value []byte) bool {
	for i := 0; i < len(value); {
		if c := value[i]; c < utf8.RuneSelf {
			if 'A' <= c && c <= 'Z' {
				return false
			}
			i++
			continue
		}
		r, size := utf8.DecodeRune(value[i:])
		if r == utf8.RuneError && size == 1 {
			return false
		}
		if unicode.ToLower(r) != r {
			return false
		}
		i += size
	}
	return true
}

func equalRekeyList(a, b *RekeyList) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// ValidateRekeyList checks a rekey-to list record against the rest of the
// profile. Under rekey: refused the list is "only these"; under a spending-key
// rekey it is "plus cosigned", which needs a cosigner, since without one the
// spending key could already rekey anywhere and the list would add nothing.
func (metadata *Metadata) ValidateRekeyList() error {
	listProofs := 0
	for _, arg := range metadata.DerivedArgs {
		if arg.Kind == DerivedArgRekeyListProof {
			listProofs++
			if metadata.RekeyList == nil || arg.Parameter != RekeyListEntriesParameter {
				return fmt.Errorf("a rekey-list proof argument needs the rekey-to list over %s", RekeyListEntriesParameter)
			}
		}
	}
	list := metadata.RekeyList
	if list == nil {
		return nil
	}
	switch {
	case list.Contract != RekeyListContractV1:
		return fmt.Errorf("unsupported rekey-to list contract %q", list.Contract)
	case list.Depth != rekeylist.Depth:
		return fmt.Errorf("rekey-to list depth %d, want %d", list.Depth, rekeylist.Depth)
	case metadata.Rekey == RekeySpendingKey && metadata.Cosigner == nil:
		return fmt.Errorf("a rekey-to list beside a spending-key rekey (%s) needs a cosigner", RekeyPlusCosigned)
	case listProofs != 1:
		return fmt.Errorf("a rekey-to list needs exactly one rekey-list proof argument, got %d", listProofs)
	}
	if list.RootHex != "" {
		if _, err := DecodeCanonicalHex("rekey-to list root", list.RootHex, 32, 32); err != nil {
			return err
		}
	}
	return nil
}
