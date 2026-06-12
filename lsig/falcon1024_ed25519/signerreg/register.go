// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerreg registers dual Falcon-1024 + Ed25519 signer-side providers.
package signerreg

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/mnemonic/bip39impl"
	"github.com/aplane-algo/aplane/internal/signing"
	dsafamilyreg "github.com/aplane-algo/aplane/lsig/dsafamily/signerreg"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falcon1024ed25519 "github.com/aplane-algo/aplane/lsig/falcon1024_ed25519"
	"github.com/aplane-algo/aplane/lsig/falcon1024_ed25519/signerops"
)

var registerSignerOnce sync.Once

// RegisterSigner wires every dual Falcon-1024 + Ed25519 signer-side registry entry.
func RegisterSigner() {
	registerSignerOnce.Do(func() {
		signingOps := signerops.New()
		keygenOps := signerops.New()
		dsafamilyreg.RegisterSigner(dsafamilyreg.SignerRegistration{
			RegisterClient: falcon1024ed25519.RegisterClient,
			SigningProvider: signing.NewLogicSigProvider(falcon1024ed25519.FamilyName, map[string]signing.LogicSigSignerOps{
				falcon1024ed25519.FamilyName: signingOps,
				falcon1024ed25519.KeyTypeV1:  signingOps,
			}),
			Generators: []dsafamilyreg.GeneratorSpec{{
				Family: falcon1024ed25519.FamilyName,
				Ops: map[string]dsafamilyreg.LogicSigKeygenOps{
					falcon1024ed25519.FamilyName: keygenOps,
					falcon1024ed25519.KeyTypeV1:  keygenOps,
				},
				Mnemonic: bip39impl.NewHandler(falcon1024ed25519.FamilyName, family.MnemonicWordCount),
			}},
		})
	})
}
