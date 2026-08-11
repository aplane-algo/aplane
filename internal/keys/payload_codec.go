// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	sentrywitness "github.com/aplane-algo/aplane/internal/witness"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Payload is the usable, decoded representation of the canonical decrypted
// key payload. PrivateKey is owned by the payload and must be cleared with
// ZeroSecrets when the payload is no longer needed.
type Payload struct {
	FormatVersion          int
	Category               string
	KeyType                string
	PublicKey              []byte
	PrivateKey             []byte
	PQScheme               string
	PQAddressSalt          *byte
	Parameters             map[string]string
	LogicSigBytecode       []byte
	LogicSigDerivation     string
	LogicSigOpcodeProfile  lsigresource.OpcodeProfile
	SaltCounter            *byte
	TEALSource             string
	SigningMetadataVersion int
	BaseKeyType            string
	SigningArgs            []StoredSigningArg
	BoundedAuthorization   *boundedmeta.Metadata
	TemplateFingerprint    string
	CreatedAt              time.Time
}

// CanonicalPayloadMetadata is the non-secret projection of a canonical key
// payload used by inventory, backup, and signing setup.
type CanonicalPayloadMetadata struct {
	FormatVersion          int
	Category               string
	KeyType                string
	PublicKeyHex           string
	PQScheme               string
	PQAddressSalt          *byte
	Parameters             map[string]string
	LogicSigBytecodeHex    string
	LogicSigDerivation     string
	LogicSigOpcodeProfile  lsigresource.OpcodeProfile
	SaltCounter            *byte
	TEALSource             string
	SigningMetadataVersion int
	BaseKeyType            string
	SigningArgs            []StoredSigningArg
	BoundedAuthorization   *boundedmeta.Metadata
	TemplateFingerprint    string
	CreatedAt              string
}

// payloadWireV1 is the sole canonical JSON DTO for decrypted key payloads.
// It remains private so durable JSON field ownership stays in this package.
type payloadWireV1 struct {
	FormatVersion          *int                        `json:"format_version"`
	Category               string                      `json:"category"`
	KeyType                string                      `json:"key_type"`
	PublicKeyHex           string                      `json:"public_key,omitempty"`
	PrivateKeyHex          string                      `json:"private_key,omitempty"`
	PQScheme               string                      `json:"pq_scheme,omitempty"`
	PQAddressSalt          *byte                       `json:"pq_address_salt,omitempty"`
	Parameters             map[string]string           `json:"parameters,omitempty"`
	LogicSigBytecodeHex    string                      `json:"lsig_bytecode,omitempty"`
	LogicSigDerivation     string                      `json:"lsig_derivation,omitempty"`
	LogicSigOpcodeProfile  *lsigresource.OpcodeProfile `json:"lsig_opcode_profile,omitempty"`
	SaltCounter            *byte                       `json:"salt_counter,omitempty"`
	TEALSource             string                      `json:"teal_source,omitempty"`
	SigningMetadataVersion int                         `json:"signing_metadata_version,omitempty"`
	BaseKeyType            string                      `json:"base_key_type,omitempty"`
	SigningArgs            []StoredSigningArg          `json:"signing_args,omitempty"`
	BoundedAuthorization   *boundedmeta.Metadata       `json:"bounded_authorization,omitempty"`
	TemplateFingerprint    string                      `json:"template_fingerprint,omitempty"`
	CreatedAt              string                      `json:"created_at"`
}

const (
	// LogicSigDerivationManualCounter is the transitional manual-salt key-file
	// contract. The empty durable value also means this mode for existing keys.
	LogicSigDerivationManualCounter = "manual_counter"

	// LogicSigDerivationAlgodV13AutoSalt records that the stored bytecode is the
	// authoritative final output of algod's TEAL v13 auto-salting assembler.
	LogicSigDerivationAlgodV13AutoSalt = "algod_v13_auto_salt"
)

// NewEd25519Payload constructs a canonical native Ed25519 key payload.
func NewEd25519Payload(publicKey, privateKey []byte) *Payload {
	return &Payload{
		FormatVersion: CurrentKeyFormatVersion,
		Category:      CategoryEd25519,
		KeyType:       "ed25519",
		PublicKey:     bytes.Clone(publicKey),
		PrivateKey:    bytes.Clone(privateKey),
		CreatedAt:     time.Now().UTC().Truncate(time.Second),
	}
}

// NewNativeFalconPayload constructs a native Falcon-1024 key payload.
func NewNativeFalconPayload(publicKey, privateKey []byte, salt byte) *Payload {
	return &Payload{
		FormatVersion: CurrentKeyFormatVersion,
		Category:      CategoryNativePQ,
		KeyType:       nativefalcon.KeyType,
		PublicKey:     bytes.Clone(publicKey),
		PrivateKey:    bytes.Clone(privateKey),
		PQScheme:      nativefalcon.Scheme,
		PQAddressSalt: cloneBytePtr(&salt),
		CreatedAt:     time.Now().UTC().Truncate(time.Second),
	}
}

// NewWitnessPayload constructs a canonical signer-custodied witness payload.
func NewWitnessPayload(keyType string, publicKey, privateKey []byte) *Payload {
	return &Payload{
		FormatVersion: CurrentKeyFormatVersion,
		Category:      CategoryWitness,
		KeyType:       keyType,
		PublicKey:     bytes.Clone(publicKey),
		PrivateKey:    bytes.Clone(privateKey),
		CreatedAt:     time.Now().UTC().Truncate(time.Second),
	}
}

// NewDSALSigPayload constructs a canonical DSA-backed LogicSig key payload.
func NewDSALSigPayload(
	keyType string,
	baseKeyType string,
	publicKey []byte,
	privateKey []byte,
	parameters map[string]string,
	bytecode []byte,
	saltCounter byte,
	tealSource string,
	signingArgs []StoredSigningArg,
	templateFingerprint string,
) *Payload {
	return &Payload{
		FormatVersion:          CurrentKeyFormatVersion,
		Category:               CategoryDSALsig,
		KeyType:                keyType,
		PublicKey:              bytes.Clone(publicKey),
		PrivateKey:             bytes.Clone(privateKey),
		Parameters:             maps.Clone(parameters),
		LogicSigBytecode:       bytes.Clone(bytecode),
		SaltCounter:            SaltCounterPtr(saltCounter),
		TEALSource:             tealSource,
		SigningMetadataVersion: CurrentSigningMetadataVersion,
		BaseKeyType:            baseKeyType,
		SigningArgs:            cloneStoredSigningArgs(signingArgs),
		TemplateFingerprint:    templateFingerprint,
		CreatedAt:              time.Now().UTC().Truncate(time.Second),
	}
}

// NewAutoSaltedDSALSigPayload constructs a DSA-backed LogicSig whose final
// bytecode was auto-salted by the TEAL v13 assembler.
func NewAutoSaltedDSALSigPayload(
	keyType string,
	baseKeyType string,
	publicKey []byte,
	privateKey []byte,
	parameters map[string]string,
	bytecode []byte,
	tealSource string,
	signingArgs []StoredSigningArg,
	templateFingerprint string,
) *Payload {
	p := NewDSALSigPayload(keyType, baseKeyType, publicKey, privateKey, parameters, bytecode, 0, tealSource, signingArgs, templateFingerprint)
	p.SaltCounter = nil
	p.LogicSigDerivation = LogicSigDerivationAlgodV13AutoSalt
	p.LogicSigOpcodeProfile = lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling)
	return p
}

// NewGenericLSigPayload constructs a canonical TEAL-only LogicSig payload.
func NewGenericLSigPayload(
	keyType string,
	parameters map[string]string,
	bytecode []byte,
	saltCounter byte,
	tealSource string,
	signingArgs []StoredSigningArg,
	templateFingerprint string,
) *Payload {
	return &Payload{
		FormatVersion:          CurrentKeyFormatVersion,
		Category:               CategoryGenericLsig,
		KeyType:                keyType,
		Parameters:             maps.Clone(parameters),
		LogicSigBytecode:       bytes.Clone(bytecode),
		SaltCounter:            SaltCounterPtr(saltCounter),
		TEALSource:             tealSource,
		SigningMetadataVersion: CurrentSigningMetadataVersion,
		SigningArgs:            cloneStoredSigningArgs(signingArgs),
		TemplateFingerprint:    templateFingerprint,
		CreatedAt:              time.Now().UTC().Truncate(time.Second),
	}
}

// NewAutoSaltedGenericLSigPayload constructs a TEAL-only LogicSig whose final
// bytecode was auto-salted by the TEAL v13 assembler.
func NewAutoSaltedGenericLSigPayload(
	keyType string,
	parameters map[string]string,
	bytecode []byte,
	tealSource string,
	signingArgs []StoredSigningArg,
	templateFingerprint string,
) *Payload {
	p := NewGenericLSigPayload(keyType, parameters, bytecode, 0, tealSource, signingArgs, templateFingerprint)
	p.SaltCounter = nil
	p.LogicSigDerivation = LogicSigDerivationAlgodV13AutoSalt
	p.LogicSigOpcodeProfile = lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling)
	return p
}

// SetBoundedAuthorization attaches a validated bounded signing contract and
// upgrades this LogicSig payload to the bounded metadata version.
func (p *Payload) SetBoundedAuthorization(metadata *boundedmeta.Metadata) error {
	if p == nil {
		return incompatibleKeyFormat("key payload is nil")
	}
	if metadata == nil {
		return incompatibleKeyFormat("bounded authorization metadata is nil")
	}
	if err := metadata.Validate(); err != nil {
		return incompatibleKeyFormat("invalid bounded_authorization: %v", err)
	}
	p.BoundedAuthorization = boundedmeta.Clone(metadata)
	p.LogicSigOpcodeProfile = lsigresource.BoundedOpcodeProfile(
		lsigresource.SingleTransactionOpcodeCeiling,
		lsigresource.SingleTransactionOpcodeCeiling,
		lsigresource.SingleTransactionOpcodeCeiling,
	)
	p.SigningMetadataVersion = BoundedSigningMetadataVersion
	// Bounded metadata owns the complete argument contract. Legacy signing_args
	// must not survive the upgrade or provide a second caller-controlled layout.
	p.SigningArgs = nil
	return nil
}

// ParsePayload strictly decodes and validates canonical decrypted key JSON.
func ParsePayload(data []byte) (*Payload, error) {
	if err := validateCanonicalJSONObject(data); err != nil {
		return nil, incompatibleKeyFormat("invalid canonical payload JSON: %v", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire payloadWireV1
	if err := decoder.Decode(&wire); err != nil {
		return nil, incompatibleKeyFormat("failed to decode canonical payload: %v", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, incompatibleKeyFormat("invalid canonical payload JSON: %v", err)
	}

	payload, err := payloadFromWire(wire)
	if err != nil {
		return nil, err
	}
	if err := payload.Validate(); err != nil {
		payload.ZeroSecrets()
		return nil, err
	}
	return payload, nil
}

// MarshalPayload validates and encodes a payload using the canonical JSON
// vocabulary. The caller owns and must zero the returned plaintext buffer.
func MarshalPayload(payload *Payload) ([]byte, error) {
	if payload == nil {
		return nil, incompatibleKeyFormat("key payload is nil")
	}
	if err := payload.Validate(); err != nil {
		return nil, err
	}
	formatVersion := payload.FormatVersion
	wire := payloadWireV1{
		FormatVersion:          &formatVersion,
		Category:               payload.Category,
		KeyType:                payload.KeyType,
		PublicKeyHex:           hex.EncodeToString(payload.PublicKey),
		PrivateKeyHex:          hex.EncodeToString(payload.PrivateKey),
		PQScheme:               payload.PQScheme,
		PQAddressSalt:          cloneBytePtr(payload.PQAddressSalt),
		Parameters:             maps.Clone(payload.Parameters),
		LogicSigBytecodeHex:    hex.EncodeToString(payload.LogicSigBytecode),
		LogicSigDerivation:     payload.LogicSigDerivation,
		LogicSigOpcodeProfile:  opcodeProfilePtr(payload.LogicSigOpcodeProfile),
		SaltCounter:            cloneBytePtr(payload.SaltCounter),
		TEALSource:             payload.TEALSource,
		SigningMetadataVersion: payload.SigningMetadataVersion,
		BaseKeyType:            payload.BaseKeyType,
		SigningArgs:            cloneStoredSigningArgs(payload.SigningArgs),
		BoundedAuthorization:   boundedmeta.Clone(payload.BoundedAuthorization),
		TemplateFingerprint:    payload.TemplateFingerprint,
		CreatedAt:              payload.CreatedAt.UTC().Format(time.RFC3339),
	}
	encoded, err := json.MarshalIndent(wire, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal canonical key payload: %w", err)
	}
	return encoded, nil
}

// Validate checks the canonical category shape and category-independent value
// invariants. Provider-specific availability remains a load/sign concern.
func (p *Payload) Validate() error {
	if p == nil {
		return incompatibleKeyFormat("key payload is nil")
	}
	if p.FormatVersion != CurrentKeyFormatVersion {
		return incompatibleKeyFormat("format_version %d is not supported by this runtime; expected %d", p.FormatVersion, CurrentKeyFormatVersion)
	}
	if p.KeyType == "" || p.KeyType != strings.TrimSpace(p.KeyType) {
		return incompatibleKeyFormat("key_type must be non-empty and canonical")
	}
	if p.CreatedAt.IsZero() || p.CreatedAt.Location() != time.UTC || !p.CreatedAt.Equal(p.CreatedAt.Truncate(time.Second)) {
		return incompatibleKeyFormat("created_at must be a whole-second UTC timestamp")
	}
	if err := validateSigningArgs(p.SigningArgs); err != nil {
		return incompatibleKeyFormat("invalid signing_args: %v", err)
	}

	switch p.Category {
	case CategoryEd25519:
		if p.KeyType != "ed25519" {
			return incompatibleKeyFormat("ed25519 category requires key_type %q", "ed25519")
		}
		if err := validateEd25519Payload(p); err != nil {
			return err
		}
		return validateNonLogicSigPayload(p)
	case CategoryNativePQ:
		if err := validateNativePQPayload(p); err != nil {
			return err
		}
		return validateNoLogicSigFields(p)
	case CategoryWitness:
		if !sentrywitness.IsKeyType(p.KeyType) {
			return incompatibleKeyFormat("witness category requires a witness key type, got %q", p.KeyType)
		}
		if err := validateWitnessPayload(p); err != nil {
			return err
		}
		return validateNonLogicSigPayload(p)
	case CategoryDSALsig:
		if len(p.PublicKey) == 0 || len(p.PrivateKey) == 0 {
			return incompatibleKeyFormat("dsa_lsig requires public_key and private_key")
		}
		if p.BaseKeyType == "" || p.BaseKeyType != strings.TrimSpace(p.BaseKeyType) {
			return incompatibleKeyFormat("dsa_lsig requires canonical base_key_type")
		}
		if err := validateNoNativePQFields(p); err != nil {
			return err
		}
		return validateLogicSigFields(p)
	case CategoryGenericLsig:
		if len(p.PublicKey) != 0 || len(p.PrivateKey) != 0 {
			return incompatibleKeyFormat("generic_lsig forbids public_key and private_key")
		}
		if p.BaseKeyType != "" {
			return incompatibleKeyFormat("generic_lsig forbids base_key_type")
		}
		if err := validateNoNativePQFields(p); err != nil {
			return err
		}
		return validateLogicSigFields(p)
	default:
		return incompatibleKeyFormat("unknown category %q", p.Category)
	}
}

// Selector derives the canonical filename selector from authoritative key
// material rather than payload metadata.
//
// Selector assumes an already-validated payload: every production payload
// comes from ParsePayload (which validates) or is validated by MarshalPayload
// before anything is persisted. It keeps only the structural checks a correct
// derivation needs, so it does not repeat the expensive per-category crypto
// validation (component pair probes, ed25519 seed derivation, on-curve).
func (p *Payload) Selector() (string, error) {
	if p == nil {
		return "", incompatibleKeyFormat("key payload is nil")
	}
	switch p.Category {
	case CategoryEd25519:
		if len(p.PublicKey) != ed25519.PublicKeySize {
			return "", incompatibleKeyFormat("ed25519 public key length %d invalid (expected %d bytes)", len(p.PublicKey), ed25519.PublicKeySize)
		}
		var address types.Address
		copy(address[:], p.PublicKey)
		return address.String(), nil
	case CategoryNativePQ:
		if p.PQScheme != nativefalcon.Scheme || p.PQAddressSalt == nil {
			return "", incompatibleKeyFormat("native_pq requires scheme and address salt")
		}
		address, err := nativefalcon.Address(*p.PQAddressSalt, p.PublicKey)
		if err != nil {
			return "", incompatibleKeyFormat("derive native PQ address: %v", err)
		}
		return address.String(), nil
	case CategoryWitness:
		return sentrywitness.ID(p.KeyType, p.PublicKey)
	case CategoryDSALsig, CategoryGenericLsig:
		if len(p.LogicSigBytecode) == 0 {
			return "", incompatibleKeyFormatErr(fmt.Errorf("%w: %s requires lsig_bytecode", ErrInvalidLogicSigBytecode, p.Category))
		}
		return logicSigAddress(p.LogicSigBytecode)
	default:
		return "", incompatibleKeyFormat("unknown category %q", p.Category)
	}
}

// Metadata returns a non-secret copy of the payload metadata.
func (p *Payload) Metadata() CanonicalPayloadMetadata {
	if p == nil {
		return CanonicalPayloadMetadata{}
	}
	return CanonicalPayloadMetadata{
		FormatVersion:          p.FormatVersion,
		Category:               p.Category,
		KeyType:                p.KeyType,
		PublicKeyHex:           hex.EncodeToString(p.PublicKey),
		PQScheme:               p.PQScheme,
		PQAddressSalt:          cloneBytePtr(p.PQAddressSalt),
		Parameters:             maps.Clone(p.Parameters),
		LogicSigBytecodeHex:    hex.EncodeToString(p.LogicSigBytecode),
		LogicSigDerivation:     p.LogicSigDerivation,
		LogicSigOpcodeProfile:  p.LogicSigOpcodeProfile,
		SaltCounter:            cloneBytePtr(p.SaltCounter),
		TEALSource:             p.TEALSource,
		SigningMetadataVersion: p.SigningMetadataVersion,
		BaseKeyType:            p.BaseKeyType,
		SigningArgs:            cloneStoredSigningArgs(p.SigningArgs),
		BoundedAuthorization:   boundedmeta.Clone(p.BoundedAuthorization),
		TemplateFingerprint:    p.TemplateFingerprint,
		CreatedAt:              p.CreatedAt.UTC().Format(time.RFC3339),
	}
}

// SigningMetadata returns a non-secret copy of the durable signing-metadata
// projection shared by scan, key load, and backup restore.
func (p *Payload) SigningMetadata() SigningMetadata {
	if p == nil {
		return SigningMetadata{}
	}
	return SigningMetadata{
		Category:               p.Category,
		PQScheme:               p.PQScheme,
		PQAddressSalt:          cloneBytePtr(p.PQAddressSalt),
		BaseKeyType:            p.BaseKeyType,
		Parameters:             maps.Clone(p.Parameters),
		SigningArgs:            cloneStoredSigningArgs(p.SigningArgs),
		LogicSigOpcodeProfile:  p.LogicSigOpcodeProfile,
		SigningMetadataVersion: p.SigningMetadataVersion,
		BoundedAuthorization:   boundedmeta.Clone(p.BoundedAuthorization),
	}
}

// ZeroSecrets clears private key material owned by the payload.
func (p *Payload) ZeroSecrets() {
	if p == nil {
		return
	}
	crypto.ZeroBytes(p.PrivateKey)
	p.PrivateKey = nil
}

func payloadFromWire(wire payloadWireV1) (*Payload, error) {
	if wire.FormatVersion == nil {
		return nil, incompatibleKeyFormat("missing format_version")
	}
	publicKey, err := decodeCanonicalHex("public_key", wire.PublicKeyHex)
	if err != nil {
		return nil, err
	}
	privateKey, err := decodeCanonicalHex("private_key", wire.PrivateKeyHex)
	if err != nil {
		return nil, err
	}
	bytecode, err := decodeCanonicalHex("lsig_bytecode", wire.LogicSigBytecodeHex)
	if err != nil {
		crypto.ZeroBytes(privateKey)
		return nil, fmt.Errorf("%w: %w", ErrInvalidLogicSigBytecode, err)
	}
	createdAt, err := time.Parse(time.RFC3339, wire.CreatedAt)
	if err != nil || createdAt.Location() != time.UTC || createdAt.Format(time.RFC3339) != wire.CreatedAt {
		crypto.ZeroBytes(privateKey)
		return nil, incompatibleKeyFormat("created_at must be canonical RFC3339 UTC")
	}
	return &Payload{
		FormatVersion:          *wire.FormatVersion,
		Category:               wire.Category,
		KeyType:                wire.KeyType,
		PublicKey:              publicKey,
		PrivateKey:             privateKey,
		PQScheme:               wire.PQScheme,
		PQAddressSalt:          cloneBytePtr(wire.PQAddressSalt),
		Parameters:             maps.Clone(wire.Parameters),
		LogicSigBytecode:       bytecode,
		LogicSigDerivation:     wire.LogicSigDerivation,
		LogicSigOpcodeProfile:  opcodeProfileValue(wire.LogicSigOpcodeProfile),
		SaltCounter:            cloneBytePtr(wire.SaltCounter),
		TEALSource:             wire.TEALSource,
		SigningMetadataVersion: wire.SigningMetadataVersion,
		BaseKeyType:            wire.BaseKeyType,
		SigningArgs:            cloneStoredSigningArgs(wire.SigningArgs),
		BoundedAuthorization:   boundedmeta.Clone(wire.BoundedAuthorization),
		TemplateFingerprint:    wire.TemplateFingerprint,
		CreatedAt:              createdAt,
	}, nil
}

// decodeCanonicalHex wraps the shared boundedmeta canonicality rule with the
// key-codec contract: empty fields decode to nil (optional payload fields)
// and violations surface as typed incompatible-key-format errors.
func decodeCanonicalHex(field, value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	decoded, err := boundedmeta.DecodeCanonicalHex(field, value, 0, 0)
	if err != nil {
		return nil, incompatibleKeyFormat("%v", err)
	}
	return decoded, nil
}

func validateEd25519Payload(p *Payload) error {
	if len(p.PublicKey) != ed25519.PublicKeySize {
		return incompatibleKeyFormat("ed25519 public key length %d invalid (expected %d bytes)", len(p.PublicKey), ed25519.PublicKeySize)
	}
	if len(p.PrivateKey) != ed25519.PrivateKeySize {
		return incompatibleKeyFormat("ed25519 private key length %d invalid (expected %d bytes)", len(p.PrivateKey), ed25519.PrivateKeySize)
	}
	// Re-derive from the seed rather than trusting the stored suffix:
	// PrivateKey.Public() only copies priv[32:], so a payload with a
	// mismatched seed/suffix would otherwise validate but sign unusably.
	derived := ed25519.NewKeyFromSeed(p.PrivateKey[:ed25519.SeedSize])
	defer crypto.ZeroBytes(derived)
	if !bytes.Equal(derived, p.PrivateKey) {
		return incompatibleKeyFormat("ed25519 private key suffix does not match its seed")
	}
	if !bytes.Equal([]byte(derived[ed25519.SeedSize:]), p.PublicKey) {
		return incompatibleKeyFormat("ed25519 public key does not match private key")
	}
	return nil
}

func validateNativePQPayload(p *Payload) error {
	if p.KeyType != nativefalcon.KeyType {
		return incompatibleKeyFormat("native_pq category requires key_type %q", nativefalcon.KeyType)
	}
	if p.PQScheme != nativefalcon.Scheme {
		return incompatibleKeyFormat("native_pq requires pq_scheme %q", nativefalcon.Scheme)
	}
	if p.PQAddressSalt == nil {
		return incompatibleKeyFormat("native_pq requires pq_address_salt")
	}
	if len(p.PublicKey) != nativefalcon.PublicKeySize {
		return incompatibleKeyFormat("native Falcon public key length %d invalid (expected %d bytes)", len(p.PublicKey), nativefalcon.PublicKeySize)
	}
	if len(p.PrivateKey) != nativefalcon.PrivateKeySize {
		return incompatibleKeyFormat("native Falcon private key length %d invalid (expected %d bytes)", len(p.PrivateKey), nativefalcon.PrivateKeySize)
	}
	canonicalSalt, address, err := nativefalcon.CanonicalAddress(p.PublicKey)
	if err != nil {
		return incompatibleKeyFormat("derive native Falcon address: %v", err)
	}
	if canonicalSalt != *p.PQAddressSalt {
		return incompatibleKeyFormat("native Falcon address salt %d is not canonical (expected %d)", *p.PQAddressSalt, canonicalSalt)
	}
	if !nativefalcon.IsCompliant(address) {
		return incompatibleKeyFormat("native Falcon address is not PQ compliant")
	}
	if err := validateNativePQKeyPair(p.PQScheme, p.PublicKey, p.PrivateKey); err != nil {
		return incompatibleKeyFormat("invalid native PQ key pair: %v", err)
	}
	return nil
}

func validateNonLogicSigPayload(p *Payload) error {
	if err := validateNoNativePQFields(p); err != nil {
		return err
	}
	return validateNoLogicSigFields(p)
}

func validateNoNativePQFields(p *Payload) error {
	if p.PQScheme != "" || p.PQAddressSalt != nil {
		return incompatibleKeyFormat("category %q forbids native PQ fields", p.Category)
	}
	return nil
}

func validateWitnessPayload(p *Payload) error {
	publicSize, ok := sentrywitness.PublicKeySize(p.KeyType)
	if !ok {
		return incompatibleKeyFormat("unsupported witness key type %q", p.KeyType)
	}
	privateSize, ok := sentrywitness.PrivateKeySize(p.KeyType)
	if !ok {
		return incompatibleKeyFormat("unsupported witness key type %q", p.KeyType)
	}
	if len(p.PublicKey) != publicSize {
		return incompatibleKeyFormat("witness public key length %d invalid (expected %d bytes)", len(p.PublicKey), publicSize)
	}
	if len(p.PrivateKey) != privateSize {
		return incompatibleKeyFormat("witness private key length %d invalid (expected %d bytes)", len(p.PrivateKey), privateSize)
	}
	if err := sentrywitness.ValidatePair(p.KeyType, p.PublicKey, p.PrivateKey); err != nil {
		return incompatibleKeyFormat("invalid witness key pair: %v", err)
	}
	return nil
}

func validateNoLogicSigFields(p *Payload) error {
	if len(p.Parameters) != 0 || len(p.LogicSigBytecode) != 0 || p.LogicSigDerivation != "" || p.LogicSigOpcodeProfile != (lsigresource.OpcodeProfile{}) || p.SaltCounter != nil ||
		p.TEALSource != "" || p.SigningMetadataVersion != 0 || p.BaseKeyType != "" ||
		len(p.SigningArgs) != 0 || p.BoundedAuthorization != nil || p.TemplateFingerprint != "" {
		return incompatibleKeyFormat("category %q forbids LogicSig fields", p.Category)
	}
	return nil
}

func validateLogicSigFields(p *Payload) error {
	if len(p.LogicSigBytecode) == 0 {
		return incompatibleKeyFormatErr(fmt.Errorf("%w: %s requires lsig_bytecode", ErrInvalidLogicSigBytecode, p.Category))
	}
	switch p.LogicSigDerivation {
	case "", LogicSigDerivationManualCounter:
		if p.SaltCounter == nil {
			return ErrMissingLogicSigSaltCounter
		}
	case LogicSigDerivationAlgodV13AutoSalt:
		if p.SaltCounter != nil {
			return incompatibleKeyFormat("%s derivation forbids salt_counter", LogicSigDerivationAlgodV13AutoSalt)
		}
		version, n := binary.Uvarint(p.LogicSigBytecode)
		if n <= 0 || version < 13 {
			return incompatibleKeyFormat("%s derivation requires final TEAL v13+ bytecode", LogicSigDerivationAlgodV13AutoSalt)
		}
		if err := p.LogicSigOpcodeProfile.Validate(p.BoundedAuthorization != nil); err != nil {
			return incompatibleKeyFormat("invalid lsig_opcode_profile: %v", err)
		}
	default:
		return incompatibleKeyFormat("unsupported lsig_derivation %q", p.LogicSigDerivation)
	}
	if p.BoundedAuthorization == nil {
		if p.SigningMetadataVersion != CurrentSigningMetadataVersion {
			return incompatibleKeyFormat("%s without bounded_authorization requires signing_metadata_version %d", p.Category, CurrentSigningMetadataVersion)
		}
	} else {
		if p.SigningMetadataVersion != BoundedSigningMetadataVersion {
			return incompatibleKeyFormat("%s with bounded_authorization requires signing_metadata_version %d", p.Category, BoundedSigningMetadataVersion)
		}
		if p.Category != CategoryDSALsig {
			return incompatibleKeyFormat("bounded_authorization requires dsa_lsig category")
		}
		if err := p.BoundedAuthorization.Validate(); err != nil {
			return incompatibleKeyFormat("invalid bounded_authorization: %v", err)
		}
		if p.BoundedAuthorization.RequiresAdminKey() {
			parameterPublicKey, err := decodeCanonicalHex(boundedmeta.AdminPublicKeyParameter, p.Parameters[boundedmeta.AdminPublicKeyParameter])
			if err != nil {
				return err
			}
			metadataPublicKey, err := boundedmeta.ParseAdminPublicKey(p.BoundedAuthorization.AdminPublicKeyHex)
			if err != nil {
				return incompatibleKeyFormat("invalid bounded_authorization: %v", err)
			}
			if !bytes.Equal(parameterPublicKey, metadataPublicKey) {
				return incompatibleKeyFormat("bounded_authorization admin public key does not match parameters.%s", boundedmeta.AdminPublicKeyParameter)
			}
		}
		if p.BoundedAuthorization.Sentry != nil {
			parameterPublicKey, err := decodeCanonicalHex(boundedmeta.SentryPublicKeyParameter, p.Parameters[boundedmeta.SentryPublicKeyParameter])
			if err != nil {
				return err
			}
			metadataPublicKey, err := boundedmeta.DecodeCanonicalHex(
				"bounded sentry public key",
				p.BoundedAuthorization.Sentry.PublicKeyHex,
				boundedmeta.SentryPublicKeySizeV1,
				boundedmeta.SentryPublicKeySizeV1,
			)
			if err != nil {
				return incompatibleKeyFormat("invalid bounded_authorization: %v", err)
			}
			if !bytes.Equal(parameterPublicKey, metadataPublicKey) {
				return incompatibleKeyFormat("bounded_authorization sentry public key does not match parameters.%s", boundedmeta.SentryPublicKeyParameter)
			}
		}
		if len(p.SigningArgs) != 0 {
			return incompatibleKeyFormat("bounded1 forbids caller-supplied signing_args")
		}
		expectedSize := len(p.LogicSigBytecode)
		for _, slot := range p.BoundedAuthorization.ArgumentLayout {
			expectedSize += slot.MaxSize
		}
		if p.BoundedAuthorization.PostSigningLogicSigSize != expectedSize {
			return incompatibleKeyFormat("bounded_authorization post_signing_lsig_size %d does not match derived size %d", p.BoundedAuthorization.PostSigningLogicSigSize, expectedSize)
		}
	}
	address, err := logicSigAddressBytes(p.LogicSigBytecode)
	if err != nil {
		return incompatibleKeyFormatErr(fmt.Errorf("%w: failed to derive LogicSig address: %v", ErrInvalidLogicSigBytecode, err))
	}
	if lsigsalt.IsOnCurve(address) {
		return incompatibleKeyFormatErr(ErrLogicSigAddressOnCurve)
	}
	return nil
}

func validateSigningArgs(args []StoredSigningArg) error {
	seen := make(map[string]struct{}, len(args))
	for i, arg := range args {
		if arg.Name == "" || arg.Name != strings.TrimSpace(arg.Name) {
			return fmt.Errorf("entry %d has a missing or non-canonical name", i)
		}
		if _, exists := seen[arg.Name]; exists {
			return fmt.Errorf("duplicate name %q", arg.Name)
		}
		seen[arg.Name] = struct{}{}
		switch arg.Type {
		case "bytes", "string", "uint64":
		default:
			return fmt.Errorf("entry %q has unsupported type %q", arg.Name, arg.Type)
		}
		if arg.ByteLength < 0 {
			return fmt.Errorf("entry %q has negative byte_length", arg.Name)
		}
	}
	return nil
}

func validateCanonicalJSONObject(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return fmt.Errorf("top-level value must be an object")
	}
	if err := consumeJSONObject(decoder); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func consumeJSONObject(decoder *json.Decoder) error {
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok {
			return fmt.Errorf("object member name is not a string")
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("duplicate object member %q", name)
		}
		seen[name] = struct{}{}
		if err := consumeJSONValue(decoder); err != nil {
			return err
		}
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('}') {
		return fmt.Errorf("unterminated object")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return fmt.Errorf("null values are not canonical")
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		return consumeJSONObject(decoder)
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("unterminated array")
		}
		return nil
	default:
		return fmt.Errorf("unexpected delimiter %q", delim)
	}
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return fmt.Errorf("trailing data: %w", err)
	}
	return nil
}

func cloneStoredSigningArgs(args []StoredSigningArg) []StoredSigningArg {
	if len(args) == 0 {
		return nil
	}
	return append([]StoredSigningArg(nil), args...)
}

func opcodeProfilePtr(profile lsigresource.OpcodeProfile) *lsigresource.OpcodeProfile {
	if profile == (lsigresource.OpcodeProfile{}) {
		return nil
	}
	copy := profile
	return &copy
}

func opcodeProfileValue(profile *lsigresource.OpcodeProfile) lsigresource.OpcodeProfile {
	if profile == nil {
		return lsigresource.OpcodeProfile{}
	}
	return *profile
}

func cloneBytePtr(value *byte) *byte {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
