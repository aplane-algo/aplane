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

	"github.com/aplane-algo/aplane/internal/rekeylist"
	"github.com/aplane-algo/aplane/internal/witness"
)

const (
	// Contract is the bounded account contract. "bounded2" is a working name: it
	// replaced bounded1 in place, with a rekey setting where bounded1 had
	// administrative operations.
	Contract                    = "bounded2"
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
	CosignerSignatureSlot             = "cosigner_signature"
	CosignerComponentKeyTypeV1        = witness.Falcon1024V1
	CosignerPublicKeySizeV1           = witness.Falcon1024PublicKeySize
	CosignerSignatureMaxSizeV1        = witness.Falcon1024SignatureSize
	MaximumProfileFee                 = 10_000
)

// The timelock policies require FirstValid >= unlock_round. They take no author
// TEAL, so they have no *Custom form.
const (
	Layer3PolicyTimelock                = "timelock"
	Layer3PolicyFixedAllowlistTimelock  = "fixed_allowlist_timelock"
	Layer3PolicyMerkleAllowlistTimelock = "merkle_allowlist_timelock"
)

// Layer3PolicyNone compiles no Layer 3: the envelope's transfer kinds and fee
// ceiling, and the spending signature, are the whole spending rule. It reads no
// parameter and takes no author TEAL.
const Layer3PolicyNone = "none"

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

// RekeyListContractV1 identifies the rekey-to list overlay's contract: the
// hiding tree in internal/rekeylist at its fixed depth.
const RekeyListContractV1 = "rekey_list1"

// Reserved creation parameters of a rekey-to list. The framework injects the
// entries parameter; the generator fills in the root, which it computes from
// the entries and a seed derived from the spending key.
const (
	RekeyListEntriesParameter = "bounded_rekey_to"
	RekeyListRootParameter    = "bounded_rekey_to_root"
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

// Metadata is the complete non-secret signing contract for one bounded key.
type Metadata struct {
	Contract               string                 `json:"contract"`
	BaseSignatureArgLayout SignatureArgLayout     `json:"base_signature_arg_layout"`
	SpendEffects           []string               `json:"spend_effects"`
	MaxFee                 uint64                 `json:"max_fee"`
	Rekey                  RekeySetting           `json:"rekey"`
	Cosigner               *CosignerAuthorization `json:"cosigner,omitempty"`
	RekeyList              *RekeyList             `json:"rekey_list,omitempty"`
	RuntimeArgs            []RuntimeArg           `json:"runtime_args"`
	DerivedArgs            []DerivedArg           `json:"derived_args"`
	ArgumentLayout         []ArgumentSlot         `json:"argument_layout"`
	Layer3Policy           string                 `json:"layer3_policy"`
}

// Clone returns a deep copy suitable for crossing cache and API boundaries.
func Clone(metadata *Metadata) *Metadata {
	if metadata == nil {
		return nil
	}
	cloned := *metadata
	cloned.BaseSignatureArgLayout.MaxSizes = slices.Clone(metadata.BaseSignatureArgLayout.MaxSizes)
	cloned.SpendEffects = slices.Clone(metadata.SpendEffects)
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
	if cloned.SpendEffects == nil {
		cloned.SpendEffects = []string{}
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
		slices.Equal(metadata.SpendEffects, other.SpendEffects) &&
		metadata.MaxFee == other.MaxFee &&
		metadata.Rekey == other.Rekey &&
		equalCosignerAuthorization(metadata.Cosigner, other.Cosigner) &&
		equalRekeyList(metadata.RekeyList, other.RekeyList) &&
		slices.Equal(metadata.RuntimeArgs, other.RuntimeArgs) &&
		slices.Equal(metadata.DerivedArgs, other.DerivedArgs) &&
		slices.Equal(metadata.ArgumentLayout, other.ArgumentLayout) &&
		metadata.Layer3Policy == other.Layer3Policy
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
	return nil
}

// ValidateProfile checks the template-level bounded contract fields. Instance
// fields such as the cosigner key are validated only by Validate after key
// generation.
func (metadata *Metadata) ValidateProfile() error {
	if metadata == nil {
		return fmt.Errorf("bounded authorization metadata is nil")
	}
	if metadata.Contract != Contract {
		return fmt.Errorf("unsupported bounded authorization contract %q", metadata.Contract)
	}
	if metadata.MaxFee > MaximumProfileFee {
		return fmt.Errorf("max_fee %d exceeds %s ceiling %d", metadata.MaxFee, Contract, MaximumProfileFee)
	}
	switch metadata.Layer3Policy {
	case Layer3PolicyCustom, Layer3PolicyFixedAllowlist, Layer3PolicyMerkleAllowlist,
		Layer3PolicyFixedAllowlistCustom, Layer3PolicyMerkleAllowlistCustom,
		Layer3PolicyTimelock, Layer3PolicyFixedAllowlistTimelock, Layer3PolicyMerkleAllowlistTimelock,
		Layer3PolicyNone:
	default:
		return fmt.Errorf("unsupported %s layer3_policy %q", Contract, metadata.Layer3Policy)
	}
	if err := ValidateSpendEffects(metadata.SpendEffects); err != nil {
		return err
	}
	if err := ValidateRekeySetting(metadata.Rekey); err != nil {
		return err
	}
	if err := ValidateCosignerAuthorizationProfile(metadata.Cosigner); err != nil {
		return err
	}
	if metadata.Cosigner != nil && metadata.Rekey != RekeyRefused {
		return fmt.Errorf("bounded cosigner profiles do not support a %s rekey", metadata.Rekey)
	}
	if err := metadata.ValidateRekeyList(); err != nil {
		return err
	}
	// A listed address is a way out, so only a refused account without a list
	// must leave a transfer for what it holds.
	if metadata.Rekey == RekeyRefused && metadata.RekeyList == nil {
		if err := ValidateRefusedExit(metadata.SpendEffects); err != nil {
			return err
		}
	}
	// No host rule gates a rekey, so a spending-key rekey would leave a timelock
	// before its unlock round. Generation refuses it earlier with a policy-specific
	// message; this keeps stored metadata to the same contract.
	if metadata.Rekey == RekeySpendingKey && isTimelockPolicy(metadata.Layer3Policy) {
		return fmt.Errorf("%s requires rekey %s: a spending-key rekey would leave the lock before the unlock round", metadata.Layer3Policy, RekeyRefused)
	}
	if err := ValidateSignatureLayout(metadata.BaseSignatureArgLayout); err != nil {
		return err
	}
	if err := validateArgumentLayout(metadata); err != nil {
		return err
	}
	// Layer 3 reads recipient proofs; a rekey-list proof serves the rekey path.
	recipientProofs := 0
	for _, arg := range metadata.DerivedArgs {
		if arg.Kind == DerivedArgMerkleProof {
			recipientProofs++
		}
	}
	switch metadata.Layer3Policy {
	case Layer3PolicyFixedAllowlist, Layer3PolicyFixedAllowlistCustom,
		Layer3PolicyTimelock, Layer3PolicyFixedAllowlistTimelock, Layer3PolicyNone:
		if recipientProofs != 0 {
			return fmt.Errorf("%s must not declare derived arguments", metadata.Layer3Policy)
		}
	case Layer3PolicyMerkleAllowlist, Layer3PolicyMerkleAllowlistCustom, Layer3PolicyMerkleAllowlistTimelock:
		if recipientProofs != 1 {
			return fmt.Errorf("%s requires exactly one derived Merkle proof argument", metadata.Layer3Policy)
		}
	}
	switch metadata.Layer3Policy {
	case Layer3PolicyTimelock, Layer3PolicyFixedAllowlistTimelock, Layer3PolicyMerkleAllowlistTimelock,
		Layer3PolicyNone:
		// These take no author TEAL, so nothing could read a runtime argument.
		if len(metadata.RuntimeArgs) != 0 {
			return fmt.Errorf("%s must not declare runtime arguments", metadata.Layer3Policy)
		}
	}
	return nil
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

// ValidateCosignerAuthorizationProfile checks definition-level cosigner fields.
// Instance public-key fields are validated by Metadata.Validate after key
// generation.
func ValidateCosignerAuthorizationProfile(cosigner *CosignerAuthorization) error {
	if cosigner == nil {
		return nil
	}
	if cosigner.Contract != CosignerContractV1 {
		return fmt.Errorf("unsupported bounded cosigner contract %q", cosigner.Contract)
	}
	if cosigner.ComponentKeyType != CosignerComponentKeyTypeV1 {
		return fmt.Errorf("unsupported bounded cosigner component key type %q", cosigner.ComponentKeyType)
	}
	if cosigner.SignatureMaxSize != CosignerSignatureMaxSizeV1 {
		return fmt.Errorf("bounded cosigner signature_max_size %d invalid (expected %d)", cosigner.SignatureMaxSize, CosignerSignatureMaxSizeV1)
	}
	if len(cosigner.RequiredOn) != 1 || cosigner.RequiredOn[0] != PathSpend {
		return fmt.Errorf("bounded cosigner required_on must be exactly [%s]", PathSpend)
	}
	return nil
}

func validateCosignerMetadata(cosigner *CosignerAuthorization) error {
	if cosigner == nil {
		return nil
	}
	publicKey, err := DecodeCanonicalHex("cosigner public_key", cosigner.PublicKeyHex, CosignerPublicKeySizeV1, CosignerPublicKeySizeV1)
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

// ValidateRefusedExit reports why an account that refuses rekeys could trap what it
// holds. With no rekey path and no close, a transfer is the only way anything
// leaves: pay for its ALGO, and axfer for any asset it can opt into. It still
// keeps its minimum balance, since it can never close.
func ValidateRefusedExit(spendEffects []string) error {
	switch {
	case !slices.Contains(spendEffects, SpendEffectPay):
		return fmt.Errorf("a bounded account that refuses rekeys needs pay in spend_effects, or its ALGO could never leave")
	case slices.Contains(spendEffects, SpendEffectAssetOptIn) && !slices.Contains(spendEffects, SpendEffectAxfer):
		return fmt.Errorf("a bounded account that refuses rekeys and opts into assets needs axfer in spend_effects, or an asset could never leave")
	}
	return nil
}

func isTimelockPolicy(policy string) bool {
	switch policy {
	case Layer3PolicyTimelock, Layer3PolicyFixedAllowlistTimelock, Layer3PolicyMerkleAllowlistTimelock:
		return true
	}
	return false
}

// RefusesRekeys reports whether the account has no rekey path at all.
func (metadata *Metadata) RefusesRekeys() bool {
	return metadata != nil && metadata.Rekey == RekeyRefused
}

// IsRecipientListPolicy reports whether a Layer 3 policy limits spending to a
// framework-enforced recipient list, alone or followed by a timelock or author
// TEAL. A policy it does not name is not a list.
func IsRecipientListPolicy(policy string) bool {
	switch policy {
	case Layer3PolicyFixedAllowlist, Layer3PolicyMerkleAllowlist,
		Layer3PolicyFixedAllowlistCustom, Layer3PolicyMerkleAllowlistCustom,
		Layer3PolicyFixedAllowlistTimelock, Layer3PolicyMerkleAllowlistTimelock:
		return true
	}
	return false
}

// HasRecipientList reports whether Layer 3 limits spending to a recipient list.
func (metadata *Metadata) HasRecipientList() bool {
	return metadata != nil && IsRecipientListPolicy(metadata.Layer3Policy)
}

// Contained reports whether the account can pay only listed recipients: it refuses
// rekeys and Layer 3 holds a recipient list. Fees are outside that: each is capped
// per transaction, but repeated transactions can still spend the balance on fees.
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
// helper binary, the signer, and the key codec all decode through it.
func DecodeCanonicalHex(field, value string, minSize, maxSize int) ([]byte, error) {
	if value == "" || value != strings.ToLower(value) {
		return nil, fmt.Errorf("%s must be non-empty lowercase hex", field)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", field, err)
	}
	if maxSize > 0 && (len(decoded) < minSize || len(decoded) > maxSize) {
		if minSize == maxSize {
			return nil, fmt.Errorf("%s length %d invalid (expected %d bytes)", field, len(decoded), maxSize)
		}
		return nil, fmt.Errorf("%s length %d invalid (expected %d-%d bytes)", field, len(decoded), minSize, maxSize)
	}
	return decoded, nil
}

func equalRekeyList(a, b *RekeyList) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// ValidateRekeyList checks a rekey-to list record against the rest of the
// profile. Phase 3 offers it only as "only these" (rekey: refused) and without
// a cosigner: a listed rekey on a cosigned account needs a signing route that
// skips the cosigner, which does not exist yet.
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
	case metadata.Rekey != RekeyRefused:
		return fmt.Errorf("a rekey-to list needs rekey %s (only these addresses)", RekeyRefused)
	case metadata.Cosigner != nil:
		return fmt.Errorf("a rekey-to list on a cosigned account is not supported")
	case listProofs != 1:
		return fmt.Errorf("a rekey-to list needs exactly one rekey-list proof argument, got %d", listProofs)
	}
	if list.RootHex != "" {
		root, err := hex.DecodeString(list.RootHex)
		if err != nil || len(root) != 32 {
			return fmt.Errorf("rekey-to list root must be 32 bytes of hex")
		}
	}
	return nil
}
