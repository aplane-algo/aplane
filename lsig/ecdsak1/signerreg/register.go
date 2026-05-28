// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerreg registers ecdsak1 signer-side providers.
package signerreg

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/mnemonic"
	"github.com/aplane-algo/aplane/internal/mnemonic/bip39impl"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/ecdsak1"
	"github.com/aplane-algo/aplane/lsig/ecdsak1/family"
	"github.com/aplane-algo/aplane/lsig/ecdsak1/signerops"
	falconkeygen "github.com/aplane-algo/aplane/lsig/falcon1024/keygen"
)

var registerSignerOnce sync.Once

// RegisterSigner wires every ecdsak1 signer-side registry entry. Idempotent.
func RegisterSigner() {
	registerSignerOnce.Do(func() {
		ecdsak1.RegisterClient()
		signingOps := signerops.New(nil)
		signing.Register(signing.NewLogicSigProvider(ecdsak1.FamilyName, map[string]signing.LogicSigSignerOps{
			ecdsak1.FamilyName: signingOps,
			ecdsak1.KeyTypeV1:  signingOps,
		}))
		keygenOps := signerops.New(nil)
		keygen.Register(falconkeygen.NewFalconGenerator(ecdsak1.FamilyName, map[string]falconkeygen.LogicSigKeygenOps{
			ecdsak1.FamilyName: keygenOps,
			ecdsak1.KeyTypeV1:  keygenOps,
		}))
		mnemonic.Register(bip39impl.NewHandler(ecdsak1.FamilyName, family.MnemonicWordCount))
	})
}
