// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package sentryaccount contains shared client-safe helpers for guarded
// sentry-account LogicSig providers.
package sentryaccount

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// Meta supplies common provider metadata methods for sentry-account providers
// that opt into the shared scaffold.
type Meta struct {
	KeyTypeName                 string
	BaseKeyTypeName             string
	FamilyName                  string
	DisplayNameText             string
	DescriptionText             string
	Color                       string
	SignatureSizeBytes          int
	MnemonicSchemeName          string
	MnemonicWordCountValue      int
	SupportsMnemonicImportValue bool
	VersionValue                int
	CategoryValue               string
}

func (m Meta) KeyType() string       { return m.KeyTypeName }
func (m Meta) BaseKeyType() string   { return m.BaseKeyTypeName }
func (m Meta) RoutingFamily() string { return m.FamilyName }
func (m Meta) Version() int {
	if m.VersionValue != 0 {
		return m.VersionValue
	}
	return 1
}
func (m Meta) Category() string {
	if m.CategoryValue != "" {
		return m.CategoryValue
	}
	return lsigprovider.CategoryDSALsig
}
func (m Meta) DisplayName() string                       { return m.DisplayNameText }
func (m Meta) Description() string                       { return m.DescriptionText }
func (m Meta) DisplayColor() string                      { return m.Color }
func (m Meta) CryptoSignatureSize() int                  { return m.SignatureSizeBytes }
func (m Meta) MnemonicScheme() string                    { return m.MnemonicSchemeName }
func (m Meta) MnemonicWordCount() int                    { return m.MnemonicWordCountValue }
func (m Meta) SupportsMnemonicImport() bool              { return m.SupportsMnemonicImportValue }
func (m Meta) RuntimeArgs() []lsigprovider.RuntimeArgDef { return nil }

// AlgodHolder stores the algod client used for TEAL compilation by providers
// that derive bytecode at generation time.
type AlgodHolder struct {
	mu     sync.RWMutex
	client *algod.Client
}

func (h *AlgodHolder) SetAlgodClient(client *algod.Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.client = client
}

func (h *AlgodHolder) AlgodClient() (*algod.Client, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.client == nil {
		return nil, fmt.Errorf("algod client not set: configure algod.<network>.server in config.yaml")
	}
	return h.client, nil
}

// CompileSalted compiles TEAL through algod and finds the pushbytes salt
// counter that yields an off-curve LogicSig address.
func CompileSalted(ctx context.Context, client *algod.Client, teal string) (lsigsalt.FindResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if client == nil {
		return lsigsalt.FindResult{}, fmt.Errorf("algod client not set: configure algod.<network>.server in config.yaml")
	}
	result, err := client.TealCompile([]byte(teal)).Do(ctx)
	if err != nil {
		return lsigsalt.FindResult{}, fmt.Errorf("TEAL compilation failed: %w", err)
	}
	bytecode, err := base64.StdEncoding.DecodeString(result.Result)
	if err != nil {
		return lsigsalt.FindResult{}, fmt.Errorf("failed to decode compiled bytecode: %w", err)
	}
	salted, err := lsigsalt.FindOffCurve(bytecode, lsigsalt.PushbytesMarkerLocator)
	if err != nil {
		return lsigsalt.FindResult{}, fmt.Errorf("failed to derive off-curve LogicSig address: %w", err)
	}
	return salted, nil
}

type algorithmMetadata struct {
	family            string
	signatureSize     int
	mnemonicScheme    string
	mnemonicWordCount int
	displayColor      string
}

// NewAlgorithmMetadata returns algorithm metadata for a LogicSig sentry-account
// provider that does not support user-entered mnemonic import.
func NewAlgorithmMetadata(family string, signatureSize int, mnemonicScheme string, mnemonicWordCount int, displayColor string) algorithm.SignatureMetadata {
	return algorithmMetadata{
		family:            family,
		signatureSize:     signatureSize,
		mnemonicScheme:    mnemonicScheme,
		mnemonicWordCount: mnemonicWordCount,
		displayColor:      displayColor,
	}
}

func (m algorithmMetadata) RoutingFamily() string        { return m.family }
func (m algorithmMetadata) CryptoSignatureSize() int     { return m.signatureSize }
func (m algorithmMetadata) MnemonicWordCount() int       { return m.mnemonicWordCount }
func (m algorithmMetadata) SupportsMnemonicImport() bool { return false }
func (m algorithmMetadata) MnemonicScheme() string       { return m.mnemonicScheme }
func (m algorithmMetadata) AuthorizationKind() algorithm.AuthorizationKind {
	return algorithm.AuthorizationLogicSig
}
func (m algorithmMetadata) RequiresLogicSig() bool       { return true }
func (m algorithmMetadata) CurrentLsigVersion() int      { return 1 }
func (m algorithmMetadata) SupportedLsigVersions() []int { return []int{1} }
func (m algorithmMetadata) DefaultDerivation() string    { return "bip39-standard" }
func (m algorithmMetadata) DisplayColor() string         { return m.displayColor }

// SentryPublicKeyParam returns the common sentry_public_key creation parameter.
func SentryPublicKeyParam(description string, publicKeySize int) lsigprovider.ParameterDef {
	return lsigprovider.ParameterDef{
		Name:        "sentry_public_key",
		Label:       "Sentry public key",
		Description: description,
		Type:        "bytes",
		Required:    true,
		MaxLength:   publicKeySize * 2,
		Example:     strings.Repeat("00", publicKeySize),
	}
}

// SentrySize describes how the sentry component signature is encoded in the
// opaque component signature blob.
type SentrySize struct {
	Fixed    int
	Variable bool
	Max      int
}

func FixedSentrySize(size int) SentrySize {
	return SentrySize{Fixed: size}
}

func VariableSentrySize(max int) SentrySize {
	return SentrySize{Variable: true, Max: max}
}

// ComponentCodec packs and unpacks a Falcon-user component signature plus a
// sentry component signature. User signature semantics are configurable so the
// package does not bake in a specific Falcon package import.
type ComponentCodec struct {
	UserLabel   string
	UserMaxSize int
	SentryLabel string
	SentrySize  SentrySize
	BlobLabel   string
}

func (c ComponentCodec) Pack(userSignature, sentrySignature []byte) ([]byte, error) {
	if err := validateVariableSignature(c.userLabel(), len(userSignature), c.UserMaxSize); err != nil {
		return nil, err
	}
	if err := c.validateSentryLength(len(sentrySignature)); err != nil {
		return nil, err
	}
	if c.SentrySize.Variable {
		out := make([]byte, 4+len(userSignature)+len(sentrySignature))
		binary.BigEndian.PutUint16(out[:2], uint16(len(userSignature)))
		copy(out[2:], userSignature)
		offset := 2 + len(userSignature)
		binary.BigEndian.PutUint16(out[offset:offset+2], uint16(len(sentrySignature)))
		copy(out[offset+2:], sentrySignature)
		return out, nil
	}
	out := make([]byte, 2+len(userSignature)+len(sentrySignature))
	binary.BigEndian.PutUint16(out[:2], uint16(len(userSignature)))
	copy(out[2:], userSignature)
	copy(out[2+len(userSignature):], sentrySignature)
	return out, nil
}

func (c ComponentCodec) Unpack(signature []byte) ([]byte, []byte, error) {
	if c.SentrySize.Variable {
		return c.unpackVariableSentry(signature)
	}
	return c.unpackFixedSentry(signature)
}

func (c ComponentCodec) unpackFixedSentry(signature []byte) ([]byte, []byte, error) {
	if len(signature) < 2+c.SentrySize.Fixed {
		return nil, nil, fmt.Errorf("%s signature blob is too short", c.blobLabel())
	}
	userLen := int(binary.BigEndian.Uint16(signature[:2]))
	if err := validateVariableSignature(c.userLabel(), userLen, c.UserMaxSize); err != nil {
		return nil, nil, err
	}
	if len(signature) != 2+userLen+c.SentrySize.Fixed {
		return nil, nil, fmt.Errorf("invalid %s signature blob length", c.blobLabel())
	}
	return signature[2 : 2+userLen], signature[2+userLen:], nil
}

func (c ComponentCodec) unpackVariableSentry(signature []byte) ([]byte, []byte, error) {
	if len(signature) < 4 {
		return nil, nil, fmt.Errorf("%s signature blob is too short", c.blobLabel())
	}
	userLen := int(binary.BigEndian.Uint16(signature[:2]))
	if err := validateVariableSignature(c.userLabel(), userLen, c.UserMaxSize); err != nil {
		return nil, nil, err
	}
	if len(signature) < 2+userLen+2 {
		return nil, nil, fmt.Errorf("%s signature blob is too short", c.blobLabel())
	}
	sentryOffset := 2 + userLen
	sentryLen := int(binary.BigEndian.Uint16(signature[sentryOffset : sentryOffset+2]))
	if err := c.validateSentryLength(sentryLen); err != nil {
		return nil, nil, err
	}
	if len(signature) != sentryOffset+2+sentryLen {
		return nil, nil, fmt.Errorf("invalid %s signature blob length", c.blobLabel())
	}
	return signature[2:sentryOffset], signature[sentryOffset+2:], nil
}

func (c ComponentCodec) validateSentryLength(length int) error {
	if c.SentrySize.Variable {
		return validateVariableSignature(c.sentryLabel(), length, c.SentrySize.Max)
	}
	if length != c.SentrySize.Fixed {
		return fmt.Errorf("%s signature length %d invalid (expected %d bytes)", c.sentryLabel(), length, c.SentrySize.Fixed)
	}
	return nil
}

func validateVariableSignature(label string, length, max int) error {
	if length <= 0 || length > max {
		return fmt.Errorf("%s signature length %d invalid (expected 1..%d bytes)", label, length, max)
	}
	return nil
}

func (c ComponentCodec) userLabel() string {
	if c.UserLabel != "" {
		return c.UserLabel
	}
	return "user"
}

func (c ComponentCodec) sentryLabel() string {
	if c.SentryLabel != "" {
		return c.SentryLabel
	}
	return "sentry"
}

func (c ComponentCodec) blobLabel() string {
	if c.BlobLabel != "" {
		return c.BlobLabel
	}
	return "guarded"
}

// DecodeSentryPublicKey decodes a hex sentry public key with optional 0x prefix
// and enforces the expected raw byte length.
func DecodeSentryPublicKey(value string, wantSize int) ([]byte, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("sentry_public_key must be hex: %w", err)
	}
	if len(decoded) != wantSize {
		return nil, fmt.Errorf("sentry_public_key length %d invalid (expected %d bytes)", len(decoded), wantSize)
	}
	return decoded, nil
}

// RejectRuntimeArgs rejects all runtime args for sentry-account providers that
// do not define user-supplied sign-time args.
func RejectRuntimeArgs(runtimeArgs map[string][]byte) error {
	if len(runtimeArgs) == 0 {
		return nil
	}
	for name := range runtimeArgs {
		return fmt.Errorf("unknown arg: %s", name)
	}
	return nil
}
