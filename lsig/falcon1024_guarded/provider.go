// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package falcon1024guarded provides the Falcon-1024 guarded-account
// LogicSig provider.
package falcon1024guarded

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/aplane-algo/aplane/internal/cosigner/keytypes"
	"github.com/aplane-algo/aplane/internal/cosigner/message"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	"github.com/aplane-algo/aplane/lsig/generictemplate"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

const (
	FamilyName  = "aplane.falcon1024-cosigner1024"
	KeyTypeV1   = keytypes.GuardedFalcon1024Cosigner1024V1
	BaseKeyType = "aplane.falcon1024.v1"

	ParamCosignerPublicKey = keytypes.ParameterCosignerPublicKey

	SignatureSize = 4 + family.MaxSignatureSize + family.MaxSignatureSize
)

// Provider implements the guarded-account LogicSig shape for a Falcon user
// component signature plus a cosigner component signature.
type Provider struct {
	keyType                  string
	familyName               string
	displayName              string
	description              string
	cosignerComponentKeyType string
	cosignerPublicKeySize    int
	signatureSize            int
	cosignerSignatureArg     string
	algodClient              *algod.Client
	algodMu                  sync.RWMutex
}

func NewProviderV1() *Provider {
	return &Provider{
		keyType:                  KeyTypeV1,
		familyName:               FamilyName,
		displayName:              "Falcon-1024 / Falcon-1024 Cosigner",
		description:              "Falcon-1024 account requiring a Falcon-1024 cosigner signature",
		cosignerComponentKeyType: witness.Falcon1024V1,
		cosignerPublicKeySize:    family.PublicKeySize,
		signatureSize:            SignatureSize,
		cosignerSignatureArg:     "cosigner_falcon1024_component_signature",
	}
}

func (p *Provider) SetAlgodClient(client *algod.Client) {
	p.algodMu.Lock()
	defer p.algodMu.Unlock()
	p.algodClient = client
}

func (p *Provider) KeyType() string       { return p.keyType }
func (p *Provider) BaseKeyType() string   { return BaseKeyType }
func (p *Provider) RoutingFamily() string { return p.familyName }
func (p *Provider) Version() int          { return 1 }
func (p *Provider) Category() string      { return lsigprovider.CategoryDSALsig }
func (p *Provider) DisplayName() string   { return p.displayName }
func (p *Provider) Description() string {
	return p.description
}
func (p *Provider) DisplayColor() string         { return family.DisplayColor }
func (p *Provider) CryptoSignatureSize() int     { return p.signatureSize }
func (p *Provider) MnemonicScheme() string       { return family.MnemonicScheme }
func (p *Provider) MnemonicWordCount() int       { return family.MnemonicWordCount }
func (p *Provider) SupportsMnemonicImport() bool { return false }
func (p *Provider) CreationParams() []lsigprovider.ParameterDef {
	return []lsigprovider.ParameterDef{{
		Name:        ParamCosignerPublicKey,
		Label:       "Cosigner public key",
		Description: "Hex-encoded Falcon-1024 cosigner public key embedded in the guarded account",
		Type:        "bytes",
		Required:    true,
		MaxLength:   p.cosignerPublicKeySize * 2,
		Example:     strings.Repeat("00", p.cosignerPublicKeySize),
	}}
}

func (p *Provider) ValidateCreationParams(params map[string]string) error {
	normalized, err := lsigprovider.NormalizeCreationParams(params, p.CreationParams())
	if err != nil {
		return err
	}
	if err := generictemplate.ValidateParameterValues(normalized, p.CreationParams()); err != nil {
		return err
	}
	_, err = decodeCosignerPublicKeyForSize(normalized[ParamCosignerPublicKey], p.cosignerPublicKeySize)
	return err
}

func (p *Provider) RuntimeArgs() []lsigprovider.RuntimeArgDef {
	return nil
}

// LogicSigOpcodeProfile is the reviewed worst-case ceiling for the fixed
// guarded Falcon program, including both verification paths.
func (p *Provider) LogicSigOpcodeProfile() lsigresource.OpcodeProfile {
	return lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling)
}

// BuildArgs assembles LogicSig args as:
//
//	arg 0: Falcon user component signature
//	arg 1: cosigner component signature
func (p *Provider) BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error) {
	if err := rejectRuntimeArgs(runtimeArgs); err != nil {
		return nil, err
	}
	userSig, cosignerSig, err := UnpackComponentSignaturesForKeyType(p.keyType, signature)
	if err != nil {
		return nil, err
	}
	return [][]byte{userSig, cosignerSig}, nil
}

func (p *Provider) DeriveLsig(ctx context.Context, publicKey []byte, params map[string]string) ([]byte, string, error) {
	result, err := p.DeriveLsigWithSalt(ctx, publicKey, params)
	if err != nil {
		return nil, "", err
	}
	return result.Bytecode, result.Address.String(), nil
}

func (p *Provider) DeriveLsigWithSalt(ctx context.Context, publicKey []byte, params map[string]string) (lsigsalt.FindResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	p.algodMu.RLock()
	client := p.algodClient
	p.algodMu.RUnlock()
	if client == nil {
		return lsigsalt.FindResult{}, fmt.Errorf("algod client not set: configure algod.<network>.server in config.yaml")
	}

	teal, err := p.GenerateTEAL(publicKey, params)
	if err != nil {
		return lsigsalt.FindResult{}, err
	}
	result, err := client.TealCompile([]byte(teal)).Do(ctx)
	if err != nil {
		return lsigsalt.FindResult{}, fmt.Errorf("TEAL compilation failed: %w", err)
	}
	bytecode, err := base64.StdEncoding.DecodeString(result.Result)
	if err != nil {
		return lsigsalt.FindResult{}, fmt.Errorf("failed to decode compiled bytecode: %w", err)
	}
	salted, err := lsigsalt.UseCompilerAutoSalted(bytecode, result.Hash)
	if err != nil {
		return lsigsalt.FindResult{}, fmt.Errorf("failed to validate compiler-auto-salted LogicSig: %w", err)
	}
	return salted, nil
}

func (p *Provider) GenerateTEAL(publicKey []byte, params map[string]string) (string, error) {
	if len(publicKey) != family.PublicKeySize {
		return "", fmt.Errorf("invalid Falcon public key size: expected %d, got %d", family.PublicKeySize, len(publicKey))
	}
	normalized, err := lsigprovider.NormalizeCreationParams(params, p.CreationParams())
	if err != nil {
		return "", err
	}
	if err := p.ValidateCreationParams(normalized); err != nil {
		return "", err
	}
	cosignerPublicKey, err := decodeCosignerPublicKeyForSize(normalized[ParamCosignerPublicKey], p.cosignerPublicKeySize)
	if err != nil {
		return "", err
	}
	cosignerVerifier := p.cosignerVerifyTEAL(cosignerPublicKey)

	return fmt.Sprintf(`#pragma version 13

// === User Falcon-1024 component signature ===
pushbytes 0x%s
pushbytes 0x%02x
concat
txn TxID
concat
sha512_256
arg 0
pushbytes 0x%s
falcon_verify
assert

%s
`, hex.EncodeToString([]byte(message.DomainTagV1)),
		byte(message.RoleUser),
		hex.EncodeToString(publicKey),
		cosignerVerifier), nil
}

func (p *Provider) cosignerVerifyTEAL(cosignerPublicKey []byte) string {
	return fmt.Sprintf(`// === Cosigner Falcon-1024 component signature ===
pushbytes 0x%s
pushbytes 0x%02x
concat
txn TxID
concat
sha512_256
arg 1
pushbytes 0x%s
falcon_verify
`, hex.EncodeToString([]byte(message.DomainTagV1)),
		byte(message.RoleCosigner),
		hex.EncodeToString(cosignerPublicKey))
}

// CompatibilityFingerprint returns the behavior-only compatibility fingerprint
// for this guarded provider. Identity/display strings (key_type, family,
// version) are excluded; the renameable base key type is projected to a stable
// base_primitive token. Provenance only — never read on the signing path.
func (p *Provider) CompatibilityFingerprint() string {
	type canonicalSpec struct {
		BasePrimitive string `json:"base_primitive"`
		SaltStyle     string `json:"salt_style"`
		Arg0          string `json:"arg0"`
		Arg1          string `json:"arg1"`
	}
	return lsigprovider.HashCompatibilitySpec(canonicalSpec{
		BasePrimitive: lsigprovider.FingerprintBasePrimitive(p.BaseKeyType()),
		SaltStyle:     string(lsigsalt.StyleAlgodAutoSalt),
		Arg0:          "user_falcon1024_component_signature",
		Arg1:          p.cosignerSignatureArg,
	})
}

// PackComponentSignatures prepares the opaque signature blob accepted by
// BuildArgs. It is intended for /sign/assemble after both component signatures
// have been verified.
func PackComponentSignatures(userSignature, cosignerSignature []byte) ([]byte, error) {
	return PackComponentSignaturesForKeyType(KeyTypeV1, userSignature, cosignerSignature)
}

func (p *Provider) PackComponentSignatures(userSignature, cosignerSignature []byte) ([]byte, error) {
	return PackComponentSignaturesForKeyType(p.keyType, userSignature, cosignerSignature)
}

func PackComponentSignaturesForKeyType(keyType string, userSignature, cosignerSignature []byte) ([]byte, error) {
	if len(userSignature) == 0 || len(userSignature) > family.MaxSignatureSize {
		return nil, fmt.Errorf("user Falcon signature length %d invalid (expected 1..%d bytes)", len(userSignature), family.MaxSignatureSize)
	}
	switch keyType {
	case KeyTypeV1:
		if len(cosignerSignature) == 0 || len(cosignerSignature) > family.MaxSignatureSize {
			return nil, fmt.Errorf("cosigner Falcon signature length %d invalid (expected 1..%d bytes)", len(cosignerSignature), family.MaxSignatureSize)
		}
		out := make([]byte, 4+len(userSignature)+len(cosignerSignature))
		binary.BigEndian.PutUint16(out[:2], uint16(len(userSignature)))
		copy(out[2:], userSignature)
		offset := 2 + len(userSignature)
		binary.BigEndian.PutUint16(out[offset:offset+2], uint16(len(cosignerSignature)))
		copy(out[offset+2:], cosignerSignature)
		return out, nil
	default:
		return nil, fmt.Errorf("key type %q is not a guarded Falcon account key type", keyType)
	}
}

func UnpackComponentSignaturesForKeyType(keyType string, signature []byte) ([]byte, []byte, error) {
	switch keyType {
	case KeyTypeV1:
		return unpackFalconCosignerSignature(signature)
	default:
		return nil, nil, fmt.Errorf("key type %q is not a guarded Falcon account key type", keyType)
	}
}

func unpackFalconCosignerSignature(signature []byte) ([]byte, []byte, error) {
	if len(signature) < 4 {
		return nil, nil, fmt.Errorf("guarded signature blob is too short")
	}
	userLen := int(binary.BigEndian.Uint16(signature[:2]))
	if userLen <= 0 || userLen > family.MaxSignatureSize {
		return nil, nil, fmt.Errorf("user Falcon signature length %d invalid (expected 1..%d bytes)", userLen, family.MaxSignatureSize)
	}
	if len(signature) < 2+userLen+2 {
		return nil, nil, fmt.Errorf("guarded signature blob is too short")
	}
	cosignerOffset := 2 + userLen
	cosignerLen := int(binary.BigEndian.Uint16(signature[cosignerOffset : cosignerOffset+2]))
	if cosignerLen <= 0 || cosignerLen > family.MaxSignatureSize {
		return nil, nil, fmt.Errorf("cosigner Falcon signature length %d invalid (expected 1..%d bytes)", cosignerLen, family.MaxSignatureSize)
	}
	if len(signature) != cosignerOffset+2+cosignerLen {
		return nil, nil, fmt.Errorf("invalid guarded signature blob length")
	}
	return signature[2:cosignerOffset], signature[cosignerOffset+2:], nil
}

func decodeCosignerPublicKeyForSize(value string, wantSize int) ([]byte, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("cosigner_public_key must be hex: %w", err)
	}
	if len(decoded) != wantSize {
		return nil, fmt.Errorf("cosigner_public_key length %d invalid (expected %d bytes)", len(decoded), wantSize)
	}
	return decoded, nil
}

func rejectRuntimeArgs(runtimeArgs map[string][]byte) error {
	if len(runtimeArgs) == 0 {
		return nil
	}
	for name := range runtimeArgs {
		return fmt.Errorf("unknown arg: %s", name)
	}
	return nil
}

var (
	_ logicsigdsa.LogicSigDSA        = (*Provider)(nil)
	_ logicsigdsa.TEALGenerator      = (*Provider)(nil)
	_ logicsigdsa.SaltedDeriver      = (*Provider)(nil)
	_ lsigprovider.LSigProvider      = (*Provider)(nil)
	_ lsigprovider.SigningProvider   = (*Provider)(nil)
	_ lsigprovider.MnemonicProvider  = (*Provider)(nil)
	_ lsigprovider.AlgodConfigurable = (*Provider)(nil)
)
