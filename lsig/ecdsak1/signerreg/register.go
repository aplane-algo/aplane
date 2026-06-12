// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerreg registers ECDSA secp256k1 signer-side providers.
package signerreg

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/mnemonic/bip39impl"
	"github.com/aplane-algo/aplane/internal/signing"
	dsafamilyreg "github.com/aplane-algo/aplane/lsig/dsafamily/signerreg"
	"github.com/aplane-algo/aplane/lsig/ecdsak1"
	"github.com/aplane-algo/aplane/lsig/ecdsak1/family"
	"github.com/aplane-algo/aplane/lsig/ecdsak1/signerops"
)

var registerSignerOnce sync.Once

// RegisterSigner registers all ECDSA secp256k1 signer-side components.
// This is idempotent and safe to call multiple times.
func RegisterSigner() {
	registerSignerOnce.Do(func() {
		signingOps := signerops.New(nil)
		keygenOps := signerops.New(nil)
		dsafamilyreg.RegisterSigner(dsafamilyreg.SignerRegistration{
			RegisterClient: ecdsak1.RegisterClient,
			SigningProvider: signing.NewLogicSigProvider(ecdsak1.FamilyName, map[string]signing.LogicSigSignerOps{
				ecdsak1.FamilyName: signingOps,
				ecdsak1.KeyTypeV1:  signingOps,
			}),
			Generators: []dsafamilyreg.GeneratorSpec{{
				Family: ecdsak1.FamilyName,
				Ops: map[string]dsafamilyreg.LogicSigKeygenOps{
					ecdsak1.FamilyName: keygenOps,
					ecdsak1.KeyTypeV1:  keygenOps,
				},
				Mnemonic: bip39impl.NewHandler(ecdsak1.FamilyName, family.MnemonicWordCount),
			}},
		})
	})
}
