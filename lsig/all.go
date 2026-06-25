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
// - Register from the keystore after apstore template import
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
	"github.com/aplane-algo/aplane/lsig/corridor"
	"github.com/aplane-algo/aplane/lsig/ecdsak1"
	ecdsak1family "github.com/aplane-algo/aplane/lsig/ecdsak1/family"
	"github.com/aplane-algo/aplane/lsig/ed25519lsig"
	falcon "github.com/aplane-algo/aplane/lsig/falcon1024"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falcon1024ed25519 "github.com/aplane-algo/aplane/lsig/falcon1024_ed25519"
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
			KeyType:      falcon1024guarded.KeyTypeFalcon1024V1,
			Family:       falcon1024guarded.FamilyNameFalcon1024,
			Availability: keytypecatalog.AvailabilityLibrary,
		}, falcon1024guarded.RegisterClient)
		registerCompiledProvider(keytypecatalog.Entry{
			KeyType:      corridor.KeyTypeV1,
			Family:       corridor.FamilyName,
			Availability: keytypecatalog.AvailabilityLibrary,
		}, corridor.RegisterClient)
		registerCompiledProvider(keytypecatalog.Entry{
			KeyType:      falcon1024ed25519.KeyTypeV1,
			Family:       falcon1024ed25519.FamilyName,
			Availability: keytypecatalog.AvailabilityLibrary,
		}, falcon1024ed25519.RegisterClient)
		registerCompiledProvider(keytypecatalog.Entry{
			KeyType:      ecdsak1.KeyTypeV1,
			Family:       ecdsak1family.Name,
			Availability: keytypecatalog.AvailabilityLibrary,
		}, ecdsak1.RegisterClient)
		ed25519lsig.RegisterClient()
	})
}

func registerCompiledProvider(entry keytypecatalog.Entry, register func()) {
	keytypecatalog.Register(entry)
	if entry.Availability == keytypecatalog.AvailabilityDisabled {
		return
	}
	register()
}
