// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerreg registers Falcon-1024 + Ed25519 signer-side providers.
package signerreg

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/mnemonic"
	"github.com/aplane-algo/aplane/internal/mnemonic/bip39impl"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falconkeygen "github.com/aplane-algo/aplane/lsig/falcon1024/keygen"
	falcon1024ed25519 "github.com/aplane-algo/aplane/lsig/falcon1024_ed25519"
	"github.com/aplane-algo/aplane/lsig/falcon1024_ed25519/signerops"
)

var registerSignerOnce sync.Once

// RegisterSigner wires every dual Falcon-1024 + Ed25519 signer-side registry entry.
func RegisterSigner() {
	registerSignerOnce.Do(func() {
		falcon1024ed25519.RegisterClient()
		signingOps := signerops.New()
		signing.Register(signing.NewLogicSigProvider(falcon1024ed25519.FamilyName, map[string]signing.LogicSigSignerOps{
			falcon1024ed25519.FamilyName: signingOps,
			falcon1024ed25519.KeyTypeV1:  signingOps,
		}))
		keygenOps := signerops.New()
		keygen.Register(falconkeygen.NewFalconGenerator(falcon1024ed25519.FamilyName, map[string]falconkeygen.LogicSigKeygenOps{
			falcon1024ed25519.FamilyName: keygenOps,
			falcon1024ed25519.KeyTypeV1:  keygenOps,
		}))
		mnemonic.Register(bip39impl.NewHandler(falcon1024ed25519.FamilyName, family.MnemonicWordCount))
	})
}
