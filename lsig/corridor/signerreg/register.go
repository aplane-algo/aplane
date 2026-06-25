// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerreg registers corridor signer-side key-generation support.
package signerreg

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/mnemonic/bip39impl"
	"github.com/aplane-algo/aplane/lsig/corridor"
	dsafamilyreg "github.com/aplane-algo/aplane/lsig/dsafamily/signerreg"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
)

var registerSignerOnce sync.Once

// RegisterSigner wires corridor account key generation. Corridor accounts are
// pure LogicSig accounts; transaction signing happens through user and sentry
// component signatures followed by /sign/assemble.
func RegisterSigner() {
	registerSignerOnce.Do(func() {
		ops := signerops.New(nil)
		dsafamilyreg.RegisterSigner(dsafamilyreg.SignerRegistration{
			RegisterClient: corridor.RegisterClient,
			Generators: []dsafamilyreg.GeneratorSpec{{
				Family: corridor.KeyTypeV1,
				Ops: map[string]dsafamilyreg.LogicSigKeygenOps{
					corridor.KeyTypeV1: ops,
				},
				Mnemonic: bip39impl.NewHandler(corridor.KeyTypeV1, family.MnemonicWordCount),
			}},
		})
	})
}
