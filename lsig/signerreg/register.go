// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerreg registers all built-in LogicSig signer-side providers.
package signerreg

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/lsig"
	"github.com/aplane-algo/aplane/lsig/ecdsak1"
	ecdsak1family "github.com/aplane-algo/aplane/lsig/ecdsak1/family"
	ecdsak1signerreg "github.com/aplane-algo/aplane/lsig/ecdsak1/signerreg"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falconsignerreg "github.com/aplane-algo/aplane/lsig/falcon1024/signerreg"
	falcon1024ed25519 "github.com/aplane-algo/aplane/lsig/falcon1024_ed25519"
	hybridsignerreg "github.com/aplane-algo/aplane/lsig/falcon1024_ed25519/signerreg"
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
			KeyType:      falcon1024ed25519.KeyTypeV1,
			Family:       falcon1024ed25519.FamilyName,
			Availability: keytypecatalog.AvailabilityLibrary,
		}, hybridsignerreg.RegisterSigner)
		registerCompiledSigner(keytypecatalog.Entry{
			KeyType:      ecdsak1.KeyTypeV1,
			Family:       ecdsak1family.Name,
			Availability: keytypecatalog.AvailabilityLibrary,
		}, ecdsak1signerreg.RegisterSigner)
	})
}

func registerCompiledSigner(entry keytypecatalog.Entry, register func()) {
	if entry.Availability == keytypecatalog.AvailabilityDisabled {
		return
	}
	register()
}
