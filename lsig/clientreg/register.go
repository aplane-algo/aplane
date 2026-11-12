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
			KeyType: "aplane.falcon1024.v1",
			Family:  family.Name,
			// The Falcon plain host carries the bounds and the overlays, as the
			// default-enabled general bounded type it replaces did (account
			// overlays phase 6.5).
			Availability: keytypecatalog.AvailabilityDefaultEnabled,
			// A Falcon-1024 private key controls every account of the plain
			// host, with or without overlays and bounds.
			ValidRekeyTarget: true,
		}, falcon.RegisterClient)
		registerCompiledProvider(keytypecatalog.Entry{
			KeyType:      ed25519lsig.KeyTypeV1,
			Family:       ed25519lsig.FamilyName,
			Availability: keytypecatalog.AvailabilityLibrary,
			// An Ed25519 private key controls every account of the plain host.
			ValidRekeyTarget: true,
		}, ed25519lsig.RegisterClient)
		// The rotating accounts have no client-side provider; each entry only
		// makes the key type opt-in. Signer binaries register its storage,
		// stage cryptography and generator through lsig/signerreg. None is a
		// valid rekey target: a rotating account's address is its one-time
		// stage 0 program (rejectRekeyToRotating refuses such a rekey).
		registerCompiledProvider(keytypecatalog.Entry{
			KeyType:          rotatingkey.RotatingTripleXmssV1,
			Family:           rotatingkey.RotatingTripleXmssFamily,
			Availability:     keytypecatalog.AvailabilityLibrary,
			ValidRekeyTarget: false,
		}, func() {})
		registerCompiledProvider(keytypecatalog.Entry{
			KeyType:          rotatingkey.RotatingTripleSlhdsaV1,
			Family:           rotatingkey.RotatingTripleSlhdsaFamily,
			Availability:     keytypecatalog.AvailabilityLibrary,
			ValidRekeyTarget: false,
		}, func() {})
		registerCompiledProvider(keytypecatalog.Entry{
			KeyType:          rotatingkey.RotatingTripleWotscV1,
			Family:           rotatingkey.RotatingTripleWotscFamily,
			Availability:     keytypecatalog.AvailabilityLibrary,
			ValidRekeyTarget: false,
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
