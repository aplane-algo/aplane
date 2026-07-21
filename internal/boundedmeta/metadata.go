// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package boundedmeta owns the durable, non-secret bounded-authorization
// metadata stored with a LogicSig key. It deliberately has no dependency on a
// runtime template or composer registration.
package boundedmeta

import (
	"crypto/sha512"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

const (
	ContractV1                 = "bounded1"
	AdminPublicKeyParameter    = "bounded_admin_public_key"
	Layer3PolicyCustom         = "custom"
	Layer3PolicyFixedAllowlist = "fixed_allowlist"
	AdminOperationRekey        = "rekey"
	AdminAuthorizationSpend    = "spending_key"
	AdminAuthorizationAdmin    = "admin_key"
	PolicyGateNone             = "none"
	PolicyGateLayer3           = "layer3"
	SpendEffectPay             = "pay"
	SpendEffectAxfer           = "axfer"
	SpendEffectAssetOptIn      = "asset_opt_in"
	FalconAdminPublicKeySize   = 1793
	FalconAdminSignatureSize   = 1280
	ProgramBindingSize         = 32
	MaximumProfileFee          = 10_000
	adminKeyIDDomainV1         = "APLANE_BOUNDED_ADMIN_KEY_ID_V1"
)

// SignatureArgLayout is the durable maximum shape of the spending signature
// args emitted before any Layer-3 or contract-admin args.
type SignatureArgLayout struct {
	Count    int   `json:"count"`
	MaxSizes []int `json:"max_sizes"`
}

// AdminOperation records one frozen bounded operation and its authority.
type AdminOperation struct {
	Kind          string `json:"kind"`
	Authorization string `json:"authorization"`
	PolicyGate    string `json:"policy_gate"`
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

// Metadata is the complete non-secret signing contract for one bounded key.
type Metadata struct {
	Contract                string             `json:"contract"`
	BaseSignatureArgLayout  SignatureArgLayout `json:"base_signature_arg_layout"`
	SpendEffects            []string           `json:"spend_effects"`
	MaxFee                  uint64             `json:"max_fee"`
	AdminOperations         []AdminOperation   `json:"admin_operations"`
	RuntimeArgs             []RuntimeArg       `json:"runtime_args"`
	DerivedArgs             []DerivedArg       `json:"derived_args"`
	ArgumentLayout          []ArgumentSlot     `json:"argument_layout"`
	Layer3Policy            string             `json:"layer3_policy"`
	AdminPublicKeyHex       string             `json:"admin_public_key,omitempty"`
	AdminKeyID              string             `json:"admin_key_id,omitempty"`
	ProgramBindingHex       string             `json:"program_binding,omitempty"`
	PostSigningLogicSigSize int                `json:"post_signing_lsig_size"`
}

// Clone returns a deep copy suitable for crossing cache and API boundaries.
func Clone(metadata *Metadata) *Metadata {
	if metadata == nil {
		return nil
	}
	cloned := *metadata
	cloned.BaseSignatureArgLayout.MaxSizes = slices.Clone(metadata.BaseSignatureArgLayout.MaxSizes)
	cloned.SpendEffects = slices.Clone(metadata.SpendEffects)
	cloned.AdminOperations = slices.Clone(metadata.AdminOperations)
	cloned.RuntimeArgs = slices.Clone(metadata.RuntimeArgs)
	cloned.DerivedArgs = slices.Clone(metadata.DerivedArgs)
	cloned.ArgumentLayout = slices.Clone(metadata.ArgumentLayout)
	if cloned.BaseSignatureArgLayout.MaxSizes == nil {
		cloned.BaseSignatureArgLayout.MaxSizes = []int{}
	}
	if cloned.SpendEffects == nil {
		cloned.SpendEffects = []string{}
	}
	if cloned.AdminOperations == nil {
		cloned.AdminOperations = []AdminOperation{}
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
		slices.Equal(metadata.AdminOperations, other.AdminOperations) &&
		slices.Equal(metadata.RuntimeArgs, other.RuntimeArgs) &&
		slices.Equal(metadata.DerivedArgs, other.DerivedArgs) &&
		slices.Equal(metadata.ArgumentLayout, other.ArgumentLayout) &&
		metadata.Layer3Policy == other.Layer3Policy &&
		metadata.AdminPublicKeyHex == other.AdminPublicKeyHex &&
		metadata.AdminKeyID == other.AdminKeyID &&
		metadata.ProgramBindingHex == other.ProgramBindingHex &&
		metadata.PostSigningLogicSigSize == other.PostSigningLogicSigSize
}

// Validate checks the durable bounded1 vocabulary without consulting an
// installed provider or template.
func (metadata *Metadata) Validate() error {
	if err := metadata.ValidateProfile(); err != nil {
		return err
	}
	if metadata.PostSigningLogicSigSize <= 0 {
		return fmt.Errorf("post_signing_lsig_size must be positive")
	}
	if err := validateAdminMetadata(metadata, metadata.RequiresAdminKey()); err != nil {
		return err
	}
	return nil
}

// ValidateProfile checks the template-level bounded contract fields. Instance
// fields such as the rendered program binding and final LogicSig size are
// intentionally validated only by Validate after key generation.
func (metadata *Metadata) ValidateProfile() error {
	if metadata == nil {
		return fmt.Errorf("bounded authorization metadata is nil")
	}
	if metadata.Contract != ContractV1 {
		return fmt.Errorf("unsupported bounded authorization contract %q", metadata.Contract)
	}
	if metadata.MaxFee > MaximumProfileFee {
		return fmt.Errorf("max_fee %d exceeds bounded1 ceiling %d", metadata.MaxFee, MaximumProfileFee)
	}
	if metadata.Layer3Policy != Layer3PolicyCustom && metadata.Layer3Policy != Layer3PolicyFixedAllowlist {
		return fmt.Errorf("unsupported bounded1 layer3_policy %q", metadata.Layer3Policy)
	}
	if err := ValidateSpendEffects(metadata.SpendEffects); err != nil {
		return err
	}
	if err := ValidateAdminOperations(metadata.AdminOperations); err != nil {
		return err
	}
	if err := ValidateSignatureLayout(metadata.BaseSignatureArgLayout); err != nil {
		return err
	}
	if err := validateArgumentLayout(metadata); err != nil {
		return err
	}
	return nil
}

// ValidateSpendEffects enforces the frozen bounded1 spend-effect rules: at
// least one entry, known effects only, no duplicates. Both storage and
// generation consume this single rule set.
func ValidateSpendEffects(spendEffects []string) error {
	if len(spendEffects) == 0 {
		return fmt.Errorf("bounded1 requires at least one spend effect")
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

// ValidateAdminOperations enforces the frozen bounded1 admin-operation rules:
// rekey is the only kind, authorization is spending_key or admin_key, no
// duplicate kinds.
func ValidateAdminOperations(operations []AdminOperation) error {
	seen := make(map[string]struct{}, len(operations))
	for _, operation := range operations {
		if operation.Kind != AdminOperationRekey {
			return fmt.Errorf("unsupported admin operation %q", operation.Kind)
		}
		if operation.Authorization != AdminAuthorizationSpend && operation.Authorization != AdminAuthorizationAdmin {
			return fmt.Errorf("unsupported authorization %q for admin operation %q", operation.Authorization, operation.Kind)
		}
		if operation.PolicyGate != PolicyGateNone && operation.PolicyGate != PolicyGateLayer3 {
			return fmt.Errorf("unsupported policy gate %q for admin operation %q", operation.PolicyGate, operation.Kind)
		}
		if operation.Authorization == AdminAuthorizationAdmin && operation.PolicyGate != PolicyGateNone {
			return fmt.Errorf("admin-key-authorized operation %q requires policy_gate %q", operation.Kind, PolicyGateNone)
		}
		if _, exists := seen[operation.Kind]; exists {
			return fmt.Errorf("duplicate admin operation %q", operation.Kind)
		}
		seen[operation.Kind] = struct{}{}
	}
	return nil
}

// RequiresAdminKey reports whether any stored operation uses the external
// Falcon contract-admin authority.
func (metadata *Metadata) RequiresAdminKey() bool {
	if metadata == nil {
		return false
	}
	for _, operation := range metadata.AdminOperations {
		if operation.Authorization == AdminAuthorizationAdmin {
			return true
		}
	}
	return false
}

// SpendPathLogicSigSize returns the post-signing LogicSig size for the
// ordinary spend path: bytecode plus base signature args only. The stored
// PostSigningLogicSigSize additionally reserves the Falcon contract-admin
// signature slot for admin-capable profiles, which only the admin-key
// choreography attaches.
func (metadata *Metadata) SpendPathLogicSigSize() int {
	return metadata.LogicSigSizeForPath(PathSpend)
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

func validateAdminMetadata(metadata *Metadata, required bool) error {
	if !required {
		if metadata.AdminPublicKeyHex != "" || metadata.AdminKeyID != "" || metadata.ProgramBindingHex != "" {
			return fmt.Errorf("contract-admin metadata is present without an admin-key-authorized operation")
		}
		return nil
	}
	publicKey, err := DecodeCanonicalHex("admin_public_key", metadata.AdminPublicKeyHex, FalconAdminPublicKeySize, FalconAdminPublicKeySize)
	if err != nil {
		return err
	}
	if len(publicKey) == 0 || strings.TrimSpace(metadata.AdminKeyID) == "" {
		return fmt.Errorf("admin-key-authorized operation requires admin public key and key ID")
	}
	wantKeyID, err := AdminKeyID(publicKey)
	if err != nil {
		return err
	}
	if metadata.AdminKeyID != wantKeyID {
		return fmt.Errorf("admin_key_id does not match admin_public_key")
	}
	if _, err := DecodeCanonicalHex("program_binding", metadata.ProgramBindingHex, ProgramBindingSize, ProgramBindingSize); err != nil {
		return err
	}
	return nil
}

// AdminKeyID derives the frozen display identifier for a Falcon contract-admin
// public key.
func AdminKeyID(publicKey []byte) (string, error) {
	if len(publicKey) != FalconAdminPublicKeySize {
		return "", fmt.Errorf("contract admin public key length %d invalid (expected %d bytes)", len(publicKey), FalconAdminPublicKeySize)
	}
	var encoded []byte
	encoded = AppendField(encoded, []byte(adminKeyIDDomainV1))
	encoded = AppendField(encoded, publicKey)
	digest := sha512.Sum512_256(encoded)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:]), nil
}

// ParseAdminPublicKey decodes the canonical public-key representation used in
// durable metadata.
func ParseAdminPublicKey(value string) ([]byte, error) {
	return DecodeCanonicalHex("admin_public_key", value, FalconAdminPublicKeySize, FalconAdminPublicKeySize)
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
