// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package falcon1024ed25519 provides a dual Falcon-1024 / Ed25519 LogicSig
// DSA family.
package falcon1024ed25519

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

const (
	// FamilyName is the qualified registry family ("publisher.family") used as
	// the key in the keygen/mnemonic/metadata/signing registries and as the
	// provider's RoutingFamily().
	FamilyName = "aplane.falcon1024_ed25519"
	KeyTypeV1  = "aplane.falcon1024_ed25519.v1"

	ed25519PublicKeySize  = ed25519.PublicKeySize
	ed25519PrivateKeySize = ed25519.PrivateKeySize
	ed25519SignatureSize  = ed25519.SignatureSize

	PublicKeySize  = family.PublicKeySize + ed25519PublicKeySize
	PrivateKeySize = family.PrivateKeySize + ed25519PrivateKeySize
	SignatureSize  = family.MaxSignatureSize + ed25519SignatureSize
)

// Ops adapts the dual-signature family to the generic ComposedDSA engine.
type Ops struct{}

func NewOps() *Ops {
	return &Ops{}
}

func (o *Ops) PublicKeySize() int       { return PublicKeySize }
func (o *Ops) CryptoSignatureSize() int { return SignatureSize }
func (o *Ops) MnemonicScheme() string   { return family.MnemonicScheme }
func (o *Ops) MnemonicWordCount() int   { return family.MnemonicWordCount }
func (o *Ops) DisplayColor() string     { return "36" }
func (o *Ops) TEALVersion() int         { return 12 }

func (o *Ops) BuildVerifyTEAL(publicKey []byte) (string, error) {
	falconPub, edPub, err := splitPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(`// === Falcon-1024 Signature Verification ===
txn TxID
arg 0
pushbytes 0x%s
falcon_verify
assert

// === Ed25519 Signature Verification ===
txn TxID
arg 1
pushbytes 0x%s
ed25519verify_bare
`, hex.EncodeToString(falconPub), hex.EncodeToString(edPub)), nil
}

func (o *Ops) BuildSignatureArgs(signature []byte) ([][]byte, error) {
	if len(signature) < 2+ed25519SignatureSize {
		return nil, fmt.Errorf("dual signature is too short")
	}

	falconLen := int(binary.BigEndian.Uint16(signature[:2]))
	if falconLen <= 0 {
		return nil, fmt.Errorf("falcon signature is required")
	}
	if falconLen > family.MaxSignatureSize {
		return nil, fmt.Errorf("falcon signature size %d exceeds maximum %d", falconLen, family.MaxSignatureSize)
	}
	if len(signature) != 2+falconLen+ed25519SignatureSize {
		return nil, fmt.Errorf("invalid dual signature length")
	}

	falconSig := signature[2 : 2+falconLen]
	edSig := signature[2+falconLen:]
	return [][]byte{falconSig, edSig}, nil
}

func NewProviderV1() *composeddsa.ComposedDSA {
	ops := NewOps()
	return composeddsa.NewComposedDSA(composeddsa.Config{
		KeyType:     KeyTypeV1,
		FamilyName:  FamilyName,
		Version:     1,
		DisplayName: "Falcon-1024 + Ed25519",
		Description: "Dual-signature LogicSig requiring Falcon-1024 and Ed25519 signatures",
		Ops:         ops,
	})
}

func splitPublicKey(publicKey []byte) (falconPub, edPub []byte, err error) {
	if len(publicKey) != PublicKeySize {
		return nil, nil, fmt.Errorf("invalid public key size: expected %d, got %d", PublicKeySize, len(publicKey))
	}
	return publicKey[:family.PublicKeySize], publicKey[family.PublicKeySize:], nil
}

var _ composeddsa.DSAOps = (*Ops)(nil)
