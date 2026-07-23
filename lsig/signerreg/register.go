// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerreg registers all built-in LogicSig signer-side providers.
package signerreg

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/lsig"
	"github.com/aplane-algo/aplane/lsig/ed25519lsig"
	ed25519lsigsignerreg "github.com/aplane-algo/aplane/lsig/ed25519lsig/signerreg"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falconsignerreg "github.com/aplane-algo/aplane/lsig/falcon1024/signerreg"
	falcon1024guarded "github.com/aplane-algo/aplane/lsig/falcon1024_guarded"
	guardedsignerreg "github.com/aplane-algo/aplane/lsig/falcon1024_guarded/signerreg"
)

var registerSignerOnce sync.Once

// RegisterSigner registers all built-in LogicSig signer-side providers.
// This is idempotent and safe to call multiple times.
func RegisterSigner() {
	registerSignerOnce.Do(func() {
		lsig.RegisterClient()
		registerCompiledSigner(keytypecatalog.Entry{
			KeyType:      "aplane.falcon1024.v1",
			Family:       family.Name,
			Availability: keytypecatalog.AvailabilityDefaultEnabled,
		}, falconsignerreg.RegisterSigner)
		registerCompiledSigner(keytypecatalog.Entry{
			KeyType:      falcon1024guarded.KeyTypeV1,
			Family:       falcon1024guarded.FamilyName,
			Availability: keytypecatalog.AvailabilityLibrary,
		}, guardedsignerreg.RegisterSigner)
		registerCompiledSigner(keytypecatalog.Entry{
			KeyType:      ed25519lsig.KeyTypeV1,
			Family:       ed25519lsig.FamilyName,
			Availability: keytypecatalog.AvailabilityLibrary,
		}, ed25519lsigsignerreg.RegisterSigner)
	})
}

func registerCompiledSigner(entry keytypecatalog.Entry, register func()) {
	if entry.Availability == keytypecatalog.AvailabilityDisabled {
		return
	}
	register()
}
