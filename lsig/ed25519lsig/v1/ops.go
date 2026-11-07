// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package v1

import (
	"github.com/aplane-algo/aplane/internal/sigconstruction"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/ed25519lsig/family"
)

type Ops struct{}

func NewOps() *Ops {
	return &Ops{}
}

func (o *Ops) PublicKeySize() int       { return family.PublicKeySize }
func (o *Ops) CryptoSignatureSize() int { return family.MaxSignatureSize }
func (o *Ops) MnemonicScheme() string   { return family.MnemonicScheme }
func (o *Ops) MnemonicWordCount() int   { return family.MnemonicWordCount }
func (o *Ops) DisplayColor() string     { return family.DisplayColor }
func (o *Ops) TEALVersion() int         { return family.TEALVersion }

// Construction returns the signature construction these operations render.
func (o *Ops) Construction() sigconstruction.Construction { return sigconstruction.Ed25519() }

func (o *Ops) BuildVerifyTEAL(publicKey []byte) (string, error) {
	verify, err := sigconstruction.Ed25519().VerifyTEAL(publicKey, "txn TxID", 0)
	if err != nil {
		return "", err
	}
	return "// === Ed25519 Signature Verification ===\n" + verify, nil
}

func (o *Ops) BuildSignatureArgs(signature []byte) ([][]byte, error) {
	return sigconstruction.Ed25519().PackSignature(signature)
}

func (o *Ops) SignatureArgLayout() composeddsa.SignatureArgLayout {
	layout := sigconstruction.Ed25519().Layout()
	return composeddsa.SignatureArgLayout{Count: layout.Count(), MaxSizes: layout.MaxSizes()}
}

var _ composeddsa.BoundedCapableDSAOps = (*Ops)(nil)
