// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package falcon1024attested provides the Falcon-1024 attested-account
// LogicSig provider.
package falcon1024attested

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/attestor/message"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	"github.com/aplane-algo/aplane/lsig/generictemplate"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

const (
	FamilyName  = "falcon1024-attested"
	KeyTypeV1   = keytypes.AttestedFalcon1024V1
	BaseKeyType = "aplane.falcon1024.v1"

	ParamAttestorPublicKey = keytypes.ParameterAttestorPublicKey

	SignatureSize = 2 + family.MaxSignatureSize + ed25519.SignatureSize
)

// Provider implements the attested-account LogicSig shape for a Falcon user
// component signature plus an Ed25519 attestor component signature.
type Provider struct {
	algodClient *algod.Client
	algodMu     sync.RWMutex
}

func NewProviderV1() *Provider {
	return &Provider{}
}

func (p *Provider) SetAlgodClient(client *algod.Client) {
	p.algodMu.Lock()
	defer p.algodMu.Unlock()
	p.algodClient = client
}

func (p *Provider) KeyType() string     { return KeyTypeV1 }
func (p *Provider) BaseKeyType() string { return BaseKeyType }
func (p *Provider) Family() string      { return FamilyName }
func (p *Provider) Version() int        { return 1 }
func (p *Provider) Category() string    { return lsigprovider.CategoryDSALsig }
func (p *Provider) DisplayName() string { return "Falcon-1024 Attested" }
func (p *Provider) Description() string {
	return "Falcon-1024 account requiring an Ed25519 attestor signature"
}
func (p *Provider) DisplayColor() string         { return family.DisplayColor }
func (p *Provider) CryptoSignatureSize() int     { return SignatureSize }
func (p *Provider) MnemonicScheme() string       { return family.MnemonicScheme }
func (p *Provider) MnemonicWordCount() int       { return family.MnemonicWordCount }
func (p *Provider) SupportsMnemonicImport() bool { return false }
func (p *Provider) CreationParams() []lsigprovider.ParameterDef {
	return []lsigprovider.ParameterDef{{
		Name:        ParamAttestorPublicKey,
		Label:       "Attestor public key",
		Description: "Hex-encoded Ed25519 attestor public key embedded in the attested account",
		Type:        "bytes",
		Required:    true,
		MaxLength:   ed25519.PublicKeySize * 2,
		Example:     strings.Repeat("00", ed25519.PublicKeySize),
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
	_, err = decodeAttestorPublicKey(normalized[ParamAttestorPublicKey])
	return err
}

func (p *Provider) RuntimeArgs() []lsigprovider.RuntimeArgDef {
	return nil
}

// BuildArgs assembles LogicSig args as:
//
//	arg 0: Falcon user component signature
//	arg 1: Ed25519 attestor component signature
func (p *Provider) BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error) {
	if err := rejectRuntimeArgs(runtimeArgs); err != nil {
		return nil, err
	}
	userSig, attestorSig, err := UnpackComponentSignatures(signature)
	if err != nil {
		return nil, err
	}
	return [][]byte{userSig, attestorSig}, nil
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
	salted, err := lsigsalt.FindOffCurve(bytecode, lsigsalt.PushbytesMarkerLocator)
	if err != nil {
		return lsigsalt.FindResult{}, fmt.Errorf("failed to derive off-curve LogicSig address: %w", err)
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
	attestorPublicKey, err := decodeAttestorPublicKey(normalized[ParamAttestorPublicKey])
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(`#pragma version 12

// Counter marker (varied 0-255 to avoid ed25519 curve addresses)
byte 0x%s
pop

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

// === Attestor Ed25519 component signature ===
pushbytes 0x%s
pushbytes 0x%02x
concat
txn TxID
concat
sha512_256
arg 1
pushbytes 0x%s
ed25519verify_bare
`, lsigsalt.PushbytesSaltMarkerHex(0),
		hex.EncodeToString([]byte(message.DomainTagV1)),
		byte(message.RoleUser),
		hex.EncodeToString(publicKey),
		hex.EncodeToString([]byte(message.DomainTagV1)),
		byte(message.RoleAttestor),
		hex.EncodeToString(attestorPublicKey)), nil
}

func (p *Provider) CompatibilityFingerprint() string {
	type canonicalSpec struct {
		KeyType     string `json:"key_type"`
		BaseKeyType string `json:"base_key_type"`
		Family      string `json:"family"`
		Version     int    `json:"version"`
		SaltStyle   string `json:"salt_style"`
		Arg0        string `json:"arg0"`
		Arg1        string `json:"arg1"`
	}
	return lsigprovider.HashCompatibilitySpec(canonicalSpec{
		KeyType:     p.KeyType(),
		BaseKeyType: p.BaseKeyType(),
		Family:      p.Family(),
		Version:     p.Version(),
		SaltStyle:   string(lsigsalt.StylePushbytes),
		Arg0:        "user_falcon1024_component_signature",
		Arg1:        "attestor_ed25519_component_signature",
	})
}

// PackComponentSignatures prepares the opaque signature blob accepted by
// BuildArgs. It is intended for /sign/assemble after both component signatures
// have been verified.
func PackComponentSignatures(userSignature, attestorSignature []byte) ([]byte, error) {
	if len(userSignature) == 0 || len(userSignature) > family.MaxSignatureSize {
		return nil, fmt.Errorf("user Falcon signature length %d invalid (expected 1..%d bytes)", len(userSignature), family.MaxSignatureSize)
	}
	if len(attestorSignature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("attestor Ed25519 signature length %d invalid (expected %d bytes)", len(attestorSignature), ed25519.SignatureSize)
	}
	out := make([]byte, 2+len(userSignature)+len(attestorSignature))
	binary.BigEndian.PutUint16(out[:2], uint16(len(userSignature)))
	copy(out[2:], userSignature)
	copy(out[2+len(userSignature):], attestorSignature)
	return out, nil
}

func UnpackComponentSignatures(signature []byte) ([]byte, []byte, error) {
	if len(signature) < 2+ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("attested signature blob is too short")
	}
	userLen := int(binary.BigEndian.Uint16(signature[:2]))
	if userLen <= 0 || userLen > family.MaxSignatureSize {
		return nil, nil, fmt.Errorf("user Falcon signature length %d invalid (expected 1..%d bytes)", userLen, family.MaxSignatureSize)
	}
	if len(signature) != 2+userLen+ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("invalid attested signature blob length")
	}
	return signature[2 : 2+userLen], signature[2+userLen:], nil
}

func decodeAttestorPublicKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("attestor_public_key must be hex: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("attestor_public_key length %d invalid (expected %d bytes)", len(decoded), ed25519.PublicKeySize)
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
