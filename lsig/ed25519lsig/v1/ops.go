// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package v1

import (
	"encoding/hex"
	"fmt"

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

func (o *Ops) BuildVerifyTEAL(publicKey []byte) (string, error) {
	if len(publicKey) != family.PublicKeySize {
		return "", fmt.Errorf("invalid public key size: expected %d, got %d", family.PublicKeySize, len(publicKey))
	}

	return fmt.Sprintf(`// === Ed25519 Signature Verification ===
txn TxID
arg 0
pushbytes 0x%s
ed25519verify_bare
`, hex.EncodeToString(publicKey)), nil
}

func (o *Ops) BuildSignatureArgs(signature []byte) ([][]byte, error) {
	if len(signature) != family.MaxSignatureSize {
		return nil, fmt.Errorf("invalid Ed25519 signature size: expected %d, got %d", family.MaxSignatureSize, len(signature))
	}
	return [][]byte{signature}, nil
}

var _ composeddsa.DSAOps = (*Ops)(nil)
