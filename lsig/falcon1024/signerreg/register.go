// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerreg registers Falcon-1024 signer-side providers.
package signerreg

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/mnemonic/bip39impl"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/witness"
	dsafamilyreg "github.com/aplane-algo/aplane/lsig/dsafamily/signerreg"
	falcon "github.com/aplane-algo/aplane/lsig/falcon1024"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	"github.com/aplane-algo/aplane/lsig/falcon1024/keygen"
	falconkeys "github.com/aplane-algo/aplane/lsig/falcon1024/keys"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
)

var registerSignerOnce sync.Once

// RegisterSigner registers all Falcon-1024 signer-side components.
// This is idempotent and safe to call multiple times.
func RegisterSigner() {
	registerSignerOnce.Do(func() {
		signingOps := signerops.New(nil)
		keygenOps := signerops.New(nil)
		dsafamilyreg.RegisterSigner(dsafamilyreg.SignerRegistration{
			RegisterClient: falcon.RegisterClient,
			SigningProvider: signing.NewLogicSigProvider(family.Name, map[string]signing.LogicSigSignerOps{
				family.Name:            signingOps,
				"aplane.falcon1024.v1": signingOps,
			}),
			Generators: []dsafamilyreg.GeneratorSpec{{
				Family: family.Name,
				Ops: map[string]dsafamilyreg.LogicSigKeygenOps{
					family.Name:            keygenOps,
					"aplane.falcon1024.v1": keygenOps,
				},
				Mnemonic: bip39impl.NewHandler(family.Name, family.MnemonicWordCount),
			}},
			Extra: []func(){
				keygen.RegisterWitnessKeygen,
				func() {
					keytypecatalog.Register(keytypecatalog.Entry{
						KeyType:      witness.Falcon1024V1,
						Family:       "sentry-falcon1024",
						Availability: keytypecatalog.AvailabilityDefaultEnabled,
					})
				},
				falconkeys.RegisterProcessors,
			},
		})
	})
}
