// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerreg registers Falcon-1024 guarded-account signer-side
// key-generation support.
package signerreg

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/mnemonic/bip39impl"
	"github.com/aplane-algo/aplane/lsig/dsafamily"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	falcon1024guarded "github.com/aplane-algo/aplane/lsig/falcon1024_guarded"
)

var registerSignerOnce sync.Once

// RegisterSigner wires guarded-account signer-side registry entries. The
// guarded key types are pure LogicSig accounts (no transaction-signing
// provider); their generators are registered under the key-type names, so
// their BIP-39 mnemonic handlers are too.
func RegisterSigner() {
	registerSignerOnce.Do(func() {
		ops := signerops.New(nil)
		dsafamily.RegisterSigner(dsafamily.SignerRegistration{
			RegisterClient: falcon1024guarded.RegisterClient,
			Generators: []dsafamily.GeneratorSpec{
				{
					Family: falcon1024guarded.KeyTypeV1,
					Ops: map[string]dsafamily.LogicSigKeygenOps{
						falcon1024guarded.KeyTypeV1: ops,
					},
					Mnemonic: bip39impl.NewHandler(falcon1024guarded.KeyTypeV1, family.MnemonicWordCount),
				},
				{
					Family: falcon1024guarded.KeyTypeFalcon1024V1,
					Ops: map[string]dsafamily.LogicSigKeygenOps{
						falcon1024guarded.KeyTypeFalcon1024V1: ops,
					},
					Mnemonic: bip39impl.NewHandler(falcon1024guarded.KeyTypeFalcon1024V1, family.MnemonicWordCount),
				},
			},
		})
	})
}
