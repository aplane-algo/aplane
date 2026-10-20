// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package clientreg is the client-side registration entry point for the lsig
// tree: catalog rows, display metadata, sizes and address derivation, and
// nothing that needs a private key. Binaries call RegisterClient at startup;
// signer binaries reach it through lsig/signerreg.RegisterSigner, which
// registers the same metadata before the signer-only providers.
package clientreg

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/lsig/ed25519lsig"
	falcon "github.com/aplane-algo/aplane/lsig/falcon1024"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falcon1024guarded "github.com/aplane-algo/aplane/lsig/falcon1024_guarded"
)

var (
	registerClientOnce sync.Once
)

// RegisterClient registers client-safe LogicSig metadata, derivation, and catalog entries.
// This is idempotent and safe to call multiple times.
//
// Registration includes:
// - DSA-based LogicSig provider metadata and derivation
//
// YAML templates under library/templates/ are intentionally not registered here.
// They become active only after being imported into an identity keystore.
func RegisterClient() {
	registerClientOnce.Do(func() {
		registerCompiledProvider(keytypecatalog.Entry{
			KeyType:      "aplane.falcon1024.v1",
			Family:       family.Name,
			Availability: keytypecatalog.AvailabilityDefaultEnabled,
		}, falcon.RegisterClient)
		registerCompiledProvider(keytypecatalog.Entry{
			KeyType:      falcon1024guarded.KeyTypeV1,
			Family:       falcon1024guarded.FamilyName,
			Availability: keytypecatalog.AvailabilityLibrary,
		}, falcon1024guarded.RegisterClient)
		registerCompiledProvider(keytypecatalog.Entry{
			KeyType:      ed25519lsig.KeyTypeV1,
			Family:       ed25519lsig.FamilyName,
			Availability: keytypecatalog.AvailabilityLibrary,
		}, ed25519lsig.RegisterClient)
		// The rotating account has no client-side provider; the entry only
		// makes the key type opt-in. Signer binaries register its storage,
		// stage cryptography and generator through lsig/signerreg.
		registerCompiledProvider(keytypecatalog.Entry{
			KeyType:      rotatingkey.RotatingTripleHybridV1,
			Family:       rotatingkey.RotatingTripleHybridFamily,
			Availability: keytypecatalog.AvailabilityLibrary,
		}, func() {})
		registerCompiledProvider(keytypecatalog.Entry{
			KeyType:      rotatingkey.RotatingXmssTripleV1,
			Family:       rotatingkey.RotatingXmssTripleFamily,
			Availability: keytypecatalog.AvailabilityLibrary,
		}, func() {})
	})
}

func registerCompiledProvider(entry keytypecatalog.Entry, register func()) {
	keytypecatalog.Register(entry)
	if entry.Availability == keytypecatalog.AvailabilityDisabled {
		return
	}
	register()
}
