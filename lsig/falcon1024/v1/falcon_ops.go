// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package v1

import (
	"github.com/aplane-algo/aplane/internal/sigconstruction"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

// FalconOps adapts Falcon family primitives to the generic ComposedDSA engine.
type FalconOps struct{}

// NewFalconOps creates Falcon operations for generic composed DSA.
func NewFalconOps() *FalconOps {
	return &FalconOps{}
}

func (o *FalconOps) PublicKeySize() int       { return family.PublicKeySize }
func (o *FalconOps) CryptoSignatureSize() int { return family.MaxSignatureSize }
func (o *FalconOps) MnemonicScheme() string   { return family.MnemonicScheme }
func (o *FalconOps) MnemonicWordCount() int   { return family.MnemonicWordCount }
func (o *FalconOps) DisplayColor() string     { return family.DisplayColor }

// Construction returns the signature construction these operations render.
func (o *FalconOps) Construction() sigconstruction.Construction { return sigconstruction.Falcon1024() }

// BuildVerifyTEAL emits the Falcon verification footer for a LogicSig program.
func (o *FalconOps) BuildVerifyTEAL(publicKey []byte) (string, error) {
	verify, err := sigconstruction.Falcon1024().VerifyTEAL(publicKey, "txn TxID", 0)
	if err != nil {
		return "", err
	}
	return "// === Falcon-1024 Signature Verification ===\n" + verify, nil
}

// TEALVersion returns the minimum TEAL version required for Falcon verification.
func (o *FalconOps) TEALVersion() int {
	return 13
}

// BuildSignatureArgs packs Falcon signature into one LogicSig arg.
func (o *FalconOps) BuildSignatureArgs(signature []byte) ([][]byte, error) {
	return sigconstruction.Falcon1024().PackSignature(signature)
}

// SignatureArgLayout declares Falcon's single variable-length signature arg.
func (o *FalconOps) SignatureArgLayout() composeddsa.SignatureArgLayout {
	layout := sigconstruction.Falcon1024().Layout()
	return composeddsa.SignatureArgLayout{Count: layout.Count(), MaxSizes: layout.MaxSizes()}
}

var _ composeddsa.BoundedCapableDSAOps = (*FalconOps)(nil)
