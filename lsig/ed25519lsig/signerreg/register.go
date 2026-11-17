// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/mnemonic"
	"github.com/aplane-algo/aplane/internal/signing"
	dsafamilyreg "github.com/aplane-algo/aplane/lsig/dsafamily/signerreg"
	"github.com/aplane-algo/aplane/lsig/ed25519lsig"
	"github.com/aplane-algo/aplane/lsig/ed25519lsig/signerops"
)

var registerSignerOnce sync.Once

func RegisterSigner() {
	registerSignerOnce.Do(func() {
		signingOps := signerops.New()
		keygenOps := signerops.New()
		dsafamilyreg.RegisterSigner(dsafamilyreg.SignerRegistration{
			RegisterClient: ed25519lsig.RegisterClient,
			SigningProvider: signing.NewLogicSigProvider(ed25519lsig.FamilyName, map[string]signing.LogicSigSignerOps{
				ed25519lsig.FamilyName: signingOps,
				ed25519lsig.KeyTypeV1:  signingOps,
			}),
			Generators: []dsafamilyreg.GeneratorSpec{{
				Family: ed25519lsig.FamilyName,
				Ops: map[string]dsafamilyreg.LogicSigKeygenOps{
					ed25519lsig.FamilyName: keygenOps,
					ed25519lsig.KeyTypeV1:  keygenOps,
				},
				Mnemonic: mnemonic.NewEd25519Handler(ed25519lsig.FamilyName),
			}},
		})
	})
}
