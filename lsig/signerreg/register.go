// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerreg registers all built-in LogicSig signer-side providers.
package signerreg

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/lsig/clientreg"
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
		// The same catalog entries lsig/clientreg registers.
		registerCompiledSigner(clientreg.FalconPlainHostEntry(), falconsignerreg.RegisterSigner)
		registerCompiledSigner(clientreg.Ed25519PlainHostEntry(), ed25519lsigsignerreg.RegisterSigner)
		// Rotating key files are readable in every signer-side binary so
		// scans, backups and offline tools agree on them. Signing for them is
		// only available through the rotating flow.
		rotatingxmsssignerreg.Register()
		rotatingslhsignerreg.Register()
		rotatingwotscsignerreg.Register()
	})
}

func registerCompiledSigner(entry keytypecatalog.Entry, register func()) {
	if entry.Availability == keytypecatalog.AvailabilityDisabled {
		return
	}
	register()
}
