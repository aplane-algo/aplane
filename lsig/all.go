// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package lsig provides centralized registration for built-in LogicSig providers.
//
// There are two types of LogicSig providers:
//
// DSA-BASED PROVIDERS (e.g., Falcon-1024):
// - Require cryptographic key generation and signing
// - Register with: logicsigdsa, signing/scheme, algorithm, keygen, mnemonic registries
//
// TEMPLATE LIBRARY PROVIDERS:
// - YAML templates in library/templates/ are optional and identity-scoped
// - Register from the keystore after apadmin template import
//
// TO ADD A NEW PROVIDER:
// 1. Create your provider package in lsig/<provider>/
// 2. Add RegisterClient calls below
// 3. Add signer-side registration in lsig/signerreg
// 4. No other file changes required!
package lsig

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/keytypecatalog"
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
	})
}

func registerCompiledProvider(entry keytypecatalog.Entry, register func()) {
	keytypecatalog.Register(entry)
	if entry.Availability == keytypecatalog.AvailabilityDisabled {
		return
	}
	register()
}
