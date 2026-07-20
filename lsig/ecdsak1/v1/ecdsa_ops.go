// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package v1

import (
	"encoding/hex"
	"fmt"

	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/ecdsak1/family"
)

// ECDSAK1Ops adapts ecdsak1 primitives to the generic ComposedDSA engine.
type ECDSAK1Ops struct {
	base family.DSABase
}

// NewECDSAK1Ops creates ecdsak1 operations for generic composed DSA.
func NewECDSAK1Ops(base family.DSABase) *ECDSAK1Ops {
	if base == nil {
		base = family.ECDSAK1Base
	}
	return &ECDSAK1Ops{base: base}
}

func (o *ECDSAK1Ops) PublicKeySize() int       { return o.base.PublicKeySize() }
func (o *ECDSAK1Ops) CryptoSignatureSize() int { return o.base.CryptoSignatureSize() }
func (o *ECDSAK1Ops) MnemonicScheme() string   { return o.base.MnemonicScheme() }
func (o *ECDSAK1Ops) MnemonicWordCount() int   { return o.base.MnemonicWordCount() }
func (o *ECDSAK1Ops) DisplayColor() string     { return o.base.DisplayColor() }

// BuildVerifyTEAL emits secp256k1 verification footer.
// Expects signature args [r, s] as arg 0 and arg 1.
func (o *ECDSAK1Ops) BuildVerifyTEAL(publicKey []byte) (string, error) {
	if len(publicKey) != o.base.PublicKeySize() {
		return "", fmt.Errorf("invalid public key size: expected %d, got %d", o.base.PublicKeySize(), len(publicKey))
	}

	xHex := hex.EncodeToString(publicKey[:32])
	yHex := hex.EncodeToString(publicKey[32:64])

	return fmt.Sprintf(`// === ECDSA secp256k1 Signature Verification ===
txn TxID
arg 0
arg 1
pushbytes 0x%s
pushbytes 0x%s
ecdsa_verify Secp256k1
`, xHex, yHex), nil
}

// TEALVersion returns the minimum version required by ecdsa_verify.
func (o *ECDSAK1Ops) TEALVersion() int {
	return 12
}

// BuildSignatureArgs packs signature bytes into [r, s].
func (o *ECDSAK1Ops) BuildSignatureArgs(signature []byte) ([][]byte, error) {
	if len(signature) != family.MaxSignatureSize {
		return nil, fmt.Errorf("invalid ecdsak1 signature size: expected %d, got %d", family.MaxSignatureSize, len(signature))
	}

	r := make([]byte, 32)
	s := make([]byte, 32)
	copy(r, signature[:32])
	copy(s, signature[32:64])
	return [][]byte{r, s}, nil
}

func (o *ECDSAK1Ops) SignatureArgLayout() composeddsa.SignatureArgLayout {
	return composeddsa.SignatureArgLayout{Count: 2, MaxSizes: []int{32, 32}}
}

var _ composeddsa.BoundedCapableDSAOps = (*ECDSAK1Ops)(nil)
