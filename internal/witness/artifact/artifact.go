// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package artifact owns the standalone witness-key custody format. It is a
// client-side package and must not be imported by signer, keystore, or apstore
// runtime code.
package artifact

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	sentryverify "github.com/aplane-algo/aplane/internal/sentry/verify"
	"github.com/aplane-algo/aplane/internal/witness"
)

const (
	BundleSchema          = "aplane.witness-key-bundle.v1"
	PrivatePayloadSchema  = "aplane.witness-key-private.v1"
	PublicReferenceSchema = witness.PublicReferenceSchema

	ErrorUnsupportedArtifactSchema = "unsupported_artifact_schema"

	maxArtifactBytes          = 64 * 1024
	falconSeedBytes           = 64
	standaloneEnvelopeVersion = 2
	standaloneKDFTime         = 2
	standaloneKDFMemory       = 64 * 1024
	standaloneKDFThreads      = 4
	standaloneSaltBytes       = 32
	standaloneNonceBytes      = 12
	standaloneGCMTagBytes     = 16
)

var selfTestMessage = []byte("APLANE_WITNESS_KEY_SELF_TEST_V1")

// ProtocolError carries a stable machine-readable artifact failure code.
type ProtocolError struct {
	Code string
	Err  error
}

func (e *ProtocolError) Error() string {
	if e == nil || e.Err == nil {
		return "artifact protocol error"
	}
	return e.Err.Error()
}

func (e *ProtocolError) Unwrap() error { return e.Err }

// ErrorCode returns a stable protocol code when err carries one.
func ErrorCode(err error) string {
	var protocolErr *ProtocolError
	if errors.As(err, &protocolErr) {
		return protocolErr.Code
	}
	return ""
}

// Bundle is the public artifact header plus a nested standalone encryption
// envelope. Schema and public identity are readable before passphrase work.
type Bundle struct {
	Schema       string                           `json:"schema"`
	KeyType      string                           `json:"key_type"`
	WitnessKeyID string                           `json:"witness_key_id"`
	PublicKeyHex string                           `json:"public_key_hex"`
	Encryption   apcrypto.EncryptedDataStandalone `json:"encryption"`
}

// PublicReference is safe to use as an enrollment input.
type PublicReference = witness.PublicReference

type privatePayload struct {
	Schema          string `json:"schema"`
	KeyType         string `json:"key_type"`
	WitnessKeyID    string `json:"witness_key_id"`
	PublicKeyHex    string `json:"public_key_hex"`
	PrivateMaterial []byte `json:"private_material"`
	CreatedAt       string `json:"created_at"`
}

// Credential is decrypted helper-owned key material. Call Zero as soon as the
// operation completes.
type Credential struct {
	PublicReference
	PrivateMaterial []byte
	CreatedAt       time.Time
}

// Zero clears decrypted private material.
func (c *Credential) Zero() {
	if c == nil {
		return
	}
	apcrypto.ZeroBytes(c.PrivateMaterial)
	c.PrivateMaterial = nil
}

// Generate creates a new encrypted artifact and its public reference.
func Generate(passphrase []byte, now time.Time) (bundleBytes, referenceBytes []byte, reference PublicReference, err error) {
	if len(passphrase) == 0 {
		return nil, nil, PublicReference{}, fmt.Errorf("artifact passphrase is required")
	}
	publicKey, privateMaterial, err := generateKey()
	if err != nil {
		return nil, nil, PublicReference{}, err
	}
	defer apcrypto.ZeroBytes(privateMaterial)

	keyID, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		return nil, nil, PublicReference{}, err
	}
	if now.IsZero() {
		now = time.Now()
	}
	reference, err = witness.NewPublicReference(witness.Falcon1024V1, keyID, hex.EncodeToString(publicKey))
	if err != nil {
		return nil, nil, PublicReference{}, err
	}
	payload := privatePayload{
		Schema:          PrivatePayloadSchema,
		KeyType:         witness.Falcon1024V1,
		WitnessKeyID:    keyID,
		PublicKeyHex:    reference.PublicKeyHex,
		PrivateMaterial: bytes.Clone(privateMaterial),
		CreatedAt:       now.UTC().Format(time.RFC3339Nano),
	}
	defer apcrypto.ZeroBytes(payload.PrivateMaterial)
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, PublicReference{}, fmt.Errorf("encode private artifact payload: %w", err)
	}
	defer apcrypto.ZeroBytes(plaintext)
	encryptedJSON, err := apcrypto.EncryptStandalone(plaintext, passphrase)
	if err != nil {
		return nil, nil, PublicReference{}, fmt.Errorf("encrypt witness artifact: %w", err)
	}
	defer apcrypto.ZeroBytes(encryptedJSON)

	var encryption apcrypto.EncryptedDataStandalone
	if err := decodeStrict(encryptedJSON, &encryption); err != nil {
		return nil, nil, PublicReference{}, fmt.Errorf("decode generated encryption envelope: %w", err)
	}
	if err := validateEncryption(encryption); err != nil {
		return nil, nil, PublicReference{}, err
	}
	bundle := Bundle{
		Schema:       BundleSchema,
		KeyType:      witness.Falcon1024V1,
		WitnessKeyID: keyID,
		PublicKeyHex: reference.PublicKeyHex,
		Encryption:   encryption,
	}
	bundleBytes, err = json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, nil, PublicReference{}, fmt.Errorf("encode witness artifact: %w", err)
	}
	referenceBytes, err = json.MarshalIndent(reference, "", "  ")
	if err != nil {
		return nil, nil, PublicReference{}, fmt.Errorf("encode public witness reference: %w", err)
	}
	return bundleBytes, referenceBytes, reference, nil
}

// Inspect validates and returns only the artifact's public header.
func Inspect(data []byte) (PublicReference, error) {
	bundle, err := parseBundle(data)
	if err != nil {
		return PublicReference{}, err
	}
	return referenceFromBundle(bundle), nil
}

// ParsePublicReference validates a generated public sidecar independently of
// any encrypted artifact. Callers that also have an artifact must require both
// projections to match.
func ParsePublicReference(data []byte) (PublicReference, error) {
	reference, err := witness.ParsePublicReference(data)
	if errors.Is(err, witness.ErrUnsupportedPublicReferenceSchema) {
		return PublicReference{}, &ProtocolError{
			Code: ErrorUnsupportedArtifactSchema,
			Err:  err,
		}
	}
	if err != nil {
		return PublicReference{}, err
	}
	return reference, nil
}

// Open decrypts and validates an artifact. The caller must Zero the result.
func Open(data, passphrase []byte) (credential *Credential, err error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("artifact passphrase is required")
	}
	bundle, err := parseBundle(data)
	if err != nil {
		return nil, err
	}
	encryptedJSON, err := json.Marshal(bundle.Encryption)
	if err != nil {
		return nil, fmt.Errorf("encode nested encryption envelope: %w", err)
	}
	plaintext, err := apcrypto.DecryptStandalone(encryptedJSON, passphrase)
	if err != nil {
		return nil, fmt.Errorf("decrypt witness artifact: %w", err)
	}
	defer apcrypto.ZeroBytes(plaintext)

	var payload privatePayload
	defer func() { apcrypto.ZeroBytes(payload.PrivateMaterial) }()
	if err := decodeStrict(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("decode private artifact payload: %w", err)
	}
	if payload.Schema != PrivatePayloadSchema {
		return nil, &ProtocolError{Code: ErrorUnsupportedArtifactSchema, Err: fmt.Errorf("unsupported private artifact schema %q", payload.Schema)}
	}
	if payload.KeyType != bundle.KeyType || payload.WitnessKeyID != bundle.WitnessKeyID || payload.PublicKeyHex != bundle.PublicKeyHex {
		return nil, fmt.Errorf("artifact public and encrypted identity fields do not match")
	}
	credential = &Credential{
		PublicReference: referenceFromBundle(bundle),
		PrivateMaterial: payload.PrivateMaterial,
	}
	payload.PrivateMaterial = nil
	defer func() {
		if err != nil {
			credential.Zero()
		}
	}()
	credential.CreatedAt, err = time.Parse(time.RFC3339Nano, payload.CreatedAt)
	if err != nil {
		err = fmt.Errorf("invalid private artifact creation time: %w", err)
		return nil, err
	}
	if err = validateCredential(credential); err != nil {
		return nil, err
	}
	return credential, nil
}

// Verify decrypts and validates an artifact without retaining private state.
func Verify(data, passphrase []byte) (PublicReference, error) {
	credential, err := Open(data, passphrase)
	if err != nil {
		return PublicReference{}, err
	}
	defer credential.Zero()
	return credential.PublicReference, nil
}

func parseBundle(data []byte) (Bundle, error) {
	if len(data) == 0 || len(data) > maxArtifactBytes {
		return Bundle{}, fmt.Errorf("witness artifact size %d is invalid", len(data))
	}
	var bundle Bundle
	if err := decodeStrict(data, &bundle); err != nil {
		return Bundle{}, fmt.Errorf("decode witness artifact: %w", err)
	}
	if bundle.Schema != BundleSchema {
		return Bundle{}, &ProtocolError{Code: ErrorUnsupportedArtifactSchema, Err: fmt.Errorf("unsupported artifact schema %q", bundle.Schema)}
	}
	if err := validatePublicIdentity(bundle.KeyType, bundle.WitnessKeyID, bundle.PublicKeyHex); err != nil {
		return Bundle{}, err
	}
	if err := validateEncryption(bundle.Encryption); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func validatePublicIdentity(keyType, keyID, publicKeyHex string) error {
	_, err := witness.NewPublicReference(keyType, keyID, publicKeyHex)
	return err
}

func validateEncryption(encryption apcrypto.EncryptedDataStandalone) error {
	if encryption.EnvelopeVersion != standaloneEnvelopeVersion {
		return fmt.Errorf("unsupported nested encryption envelope version %d", encryption.EnvelopeVersion)
	}
	if encryption.KDFTime != standaloneKDFTime || encryption.KDFMemory != standaloneKDFMemory || encryption.KDFThreads != standaloneKDFThreads {
		return fmt.Errorf("unsupported witness artifact KDF parameters")
	}
	salt, err := base64.StdEncoding.DecodeString(encryption.Salt)
	if err != nil || len(salt) != standaloneSaltBytes {
		return fmt.Errorf("witness artifact encryption salt is invalid")
	}
	nonce, err := base64.StdEncoding.DecodeString(encryption.Nonce)
	if err != nil || len(nonce) != standaloneNonceBytes {
		return fmt.Errorf("witness artifact encryption nonce is invalid")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encryption.Ciphertext)
	if err != nil || len(ciphertext) < standaloneGCMTagBytes {
		return fmt.Errorf("witness artifact encryption ciphertext is invalid")
	}
	return nil
}

func validateCredential(credential *Credential) error {
	publicKey, err := decodeCanonicalPublicKey(credential.PublicKeyHex)
	if err != nil {
		return err
	}
	if credential.KeyType != witness.Falcon1024V1 {
		return fmt.Errorf("unsupported witness key type %q", credential.KeyType)
	}
	if len(credential.PrivateMaterial) != witness.Falcon1024PrivateKeySize {
		return fmt.Errorf("Falcon-1024 private material length %d invalid", len(credential.PrivateMaterial))
	}
	signature, err := signFalcon(credential.PrivateMaterial, selfTestMessage)
	if err != nil {
		return fmt.Errorf("Falcon-1024 artifact self-test signing failed: %w", err)
	}
	defer apcrypto.ZeroBytes(signature)
	if err := sentryverify.VerifyFalcon1024(publicKey, selfTestMessage, signature); err != nil {
		return fmt.Errorf("Falcon-1024 private material does not match public key: %w", err)
	}
	return nil
}

func generateKey() (publicKey, privateMaterial []byte, err error) {
	seed := make([]byte, falconSeedBytes)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, nil, fmt.Errorf("generate Falcon-1024 seed: %w", err)
	}
	defer apcrypto.ZeroBytes(seed)
	keyPair, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		return nil, nil, fmt.Errorf("generate Falcon-1024 key: %w", err)
	}
	defer apcrypto.ZeroBytes(keyPair.PrivateKey[:])
	return bytes.Clone(keyPair.PublicKey[:]), bytes.Clone(keyPair.PrivateKey[:]), nil
}

func signFalcon(privateKey, message []byte) ([]byte, error) {
	if len(privateKey) != witness.Falcon1024PrivateKeySize {
		return nil, fmt.Errorf("Falcon-1024 private material length %d invalid", len(privateKey))
	}
	var private falcongo.PrivateKey
	copy(private[:], privateKey)
	defer apcrypto.ZeroBytes(private[:])
	keyPair := falcongo.KeyPair{PrivateKey: private}
	defer apcrypto.ZeroBytes(keyPair.PrivateKey[:])
	signature, err := keyPair.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("Falcon-1024 signing failed: %w", err)
	}
	return signature, nil
}

func referenceFromBundle(bundle Bundle) PublicReference {
	return PublicReference{
		Schema:       PublicReferenceSchema,
		KeyType:      bundle.KeyType,
		WitnessKeyID: bundle.WitnessKeyID,
		PublicKeyHex: bundle.PublicKeyHex,
	}
}

func decodeCanonicalPublicKey(value string) ([]byte, error) {
	if value == "" || value != strings.ToLower(value) {
		return nil, fmt.Errorf("public key must be non-empty lowercase hex")
	}
	publicKey, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("public key must be canonical lowercase hex: %w", err)
	}
	if hex.EncodeToString(publicKey) != value {
		return nil, fmt.Errorf("public key must be canonical lowercase hex")
	}
	if len(publicKey) != witness.Falcon1024PublicKeySize {
		return nil, fmt.Errorf("witness public key length %d invalid (expected %d bytes)", len(publicKey), witness.Falcon1024PublicKeySize)
	}
	return publicKey, nil
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
