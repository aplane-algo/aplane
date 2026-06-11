// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerreg registers Falcon-1024 guarded-account signer-side
// key-generation support.
package signerreg

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/mnemonic"
	"github.com/aplane-algo/aplane/internal/mnemonic/bip39impl"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falconkeygen "github.com/aplane-algo/aplane/lsig/falcon1024/keygen"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	falcon1024guarded "github.com/aplane-algo/aplane/lsig/falcon1024_guarded"
)

var registerSignerOnce sync.Once

func RegisterSigner() {
	registerSignerOnce.Do(func() {
		falcon1024guarded.RegisterClient()
		ops := signerops.New(nil)
		keygen.Register(falconkeygen.NewFalconGenerator(falcon1024guarded.KeyTypeV1, map[string]falconkeygen.LogicSigKeygenOps{
			falcon1024guarded.KeyTypeV1: ops,
		}))
		keygen.Register(falconkeygen.NewFalconGenerator(falcon1024guarded.KeyTypeFalcon1024V1, map[string]falconkeygen.LogicSigKeygenOps{
			falcon1024guarded.KeyTypeFalcon1024V1: ops,
		}))
		// The guarded generators are registered under their key-type names,
		// so their BIP-39 mnemonic handlers are too: the generator resolves
		// its handler by its registered family string.
		mnemonic.Register(bip39impl.NewHandler(falcon1024guarded.KeyTypeV1, family.MnemonicWordCount))
		mnemonic.Register(bip39impl.NewHandler(falcon1024guarded.KeyTypeFalcon1024V1, family.MnemonicWordCount))
	})
}
