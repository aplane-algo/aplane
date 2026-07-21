// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package v1

import (
	"encoding/hex"
	"fmt"

	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

// FalconOps adapts Falcon family primitives to the generic ComposedDSA engine.
type FalconOps struct {
	base family.DSABase
}

// NewFalconOps creates Falcon operations for generic composed DSA.
// If base is nil, family.FalconBase is used.
func NewFalconOps(base family.DSABase) *FalconOps {
	if base == nil {
		base = family.FalconBase
	}
	return &FalconOps{base: base}
}

func (o *FalconOps) PublicKeySize() int       { return o.base.PublicKeySize() }
func (o *FalconOps) CryptoSignatureSize() int { return o.base.CryptoSignatureSize() }
func (o *FalconOps) MnemonicScheme() string   { return o.base.MnemonicScheme() }
func (o *FalconOps) MnemonicWordCount() int   { return o.base.MnemonicWordCount() }
func (o *FalconOps) DisplayColor() string     { return o.base.DisplayColor() }

// BuildVerifyTEAL emits the Falcon verification footer for a LogicSig program.
func (o *FalconOps) BuildVerifyTEAL(publicKey []byte) (string, error) {
	if len(publicKey) != o.base.PublicKeySize() {
		return "", fmt.Errorf("invalid public key size: expected %d, got %d", o.base.PublicKeySize(), len(publicKey))
	}

	return fmt.Sprintf(`// === Falcon-1024 Signature Verification ===
txn TxID
arg 0
pushbytes 0x%s
falcon_verify
`, hex.EncodeToString(publicKey)), nil
}

// TEALVersion returns the minimum TEAL version required for Falcon verification.
func (o *FalconOps) TEALVersion() int {
	return 12
}

// BuildSignatureArgs packs Falcon signature into one LogicSig arg.
func (o *FalconOps) BuildSignatureArgs(signature []byte) ([][]byte, error) {
	if len(signature) == 0 {
		return nil, fmt.Errorf("signature is required for DSA LogicSig")
	}
	return [][]byte{signature}, nil
}

// SignatureArgLayout declares Falcon's single variable-length signature arg.
func (o *FalconOps) SignatureArgLayout() composeddsa.SignatureArgLayout {
	return composeddsa.SignatureArgLayout{Count: 1, MaxSizes: []int{family.MaxSignatureSize}}
}

var _ composeddsa.BoundedCapableDSAOps = (*FalconOps)(nil)
