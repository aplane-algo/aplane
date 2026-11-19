// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerreg registers all built-in LogicSig signer-side providers.
package signerreg

import (
	"sync"

	"github.com/aplane-algo/aplane/lsig/clientreg"
	ed25519witnesskeygen "github.com/aplane-algo/aplane/lsig/ed25519lsig/keygen"
	ed25519lsigsignerreg "github.com/aplane-algo/aplane/lsig/ed25519lsig/signerreg"
	falconsignerreg "github.com/aplane-algo/aplane/lsig/falcon1024/signerreg"
	rotatingslhsignerreg "github.com/aplane-algo/aplane/lsig/rotatingtripleslhdsa/signerreg"
	rotatingwotscsignerreg "github.com/aplane-algo/aplane/lsig/rotatingtriplewotsc/signerreg"
	rotatingxmsssignerreg "github.com/aplane-algo/aplane/lsig/rotatingtriplexmss/signerreg"
)

var registerSignerOnce sync.Once

// RegisterSigner registers all built-in LogicSig signer-side providers.
// This is idempotent and safe to call multiple times.
func RegisterSigner() {
	registerSignerOnce.Do(func() {
		clientreg.RegisterClient()
		falconsignerreg.RegisterSigner()
		ed25519lsigsignerreg.RegisterSigner()
		// A cosigner key is no account type's: its cosigner node needs it
		// registered whatever the Ed25519 plain host's availability, or its
		// .cos files would no longer load.
		ed25519witnesskeygen.RegisterWitnessKeygen()
		// Rotating key files are readable in every signer-side binary so
		// scans, backups and offline tools agree on them. Signing for them is
		// only available through the rotating flow.
		rotatingxmsssignerreg.Register()
		rotatingslhsignerreg.Register()
		rotatingwotscsignerreg.Register()
	})
}
