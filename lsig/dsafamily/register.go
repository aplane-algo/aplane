// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package dsafamily holds the client-safe registration descriptor a LogicSig
// DSA family needs: LogicSig derivation, address derivation, and display
// metadata. A family declares one ClientRegistration (and, in
// lsig/dsafamily/signerreg, one SignerRegistration) instead of hand-writing
// per-registry calls, so partial registration is not representable. This
// package must not reference signer-side machinery (key generation, signing
// providers, mnemonics) so client binaries stay lean; the shared key
// generator and signer descriptor live in lsig/dsafamily/signerreg.
//
// Product-level visibility (keytypecatalog entries and availability gating)
// intentionally stays in the lsig root aggregator: which compiled key types
// are exposed is a product decision, not a family one.
package dsafamily

import (
	"github.com/aplane-algo/aplane/internal/addressderive"
	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
)

// KeyType describes one versioned key type a family compiles in.
type KeyType struct {
	// KeyType is the versioned key type, e.g. "aplane.falcon1024.v1".
	KeyType string
	// DSA is the LogicSig provider registered for the key type.
	DSA logicsigdsa.LogicSigDSA
	// AddressDeriver derives on-chain addresses for the key type; nil skips
	// address-derivation registration.
	AddressDeriver addressderive.Deriver
}

// ClientRegistration is the client-safe half of a family's capabilities:
// LogicSig derivation, address derivation, and display metadata. It must not
// reference signer-side machinery so client binaries stay lean.
type ClientRegistration struct {
	// Family is the registry family name, e.g. "falcon1024".
	Family string
	// Metadata is the family's algorithm display/derivation metadata.
	Metadata algorithm.SignatureMetadata
	// KeyTypes lists every versioned key type the family compiles in.
	KeyTypes []KeyType
	// Extra holds family-specific client-side registrations that have no
	// generic slot (e.g. registering as a composable template base).
	Extra []func()
}

// RegisterClient fans a family's client-safe capabilities out to the global
// registries. Callers guard idempotency with their own sync.Once, matching
// the per-family RegisterClient convention.
func RegisterClient(r ClientRegistration) {
	for _, kt := range r.KeyTypes {
		// First-wins: compiled families register at process start (before any
		// runtime template registration), and per-family v1 helpers may have
		// already registered the same provider in test binaries.
		logicsigdsa.RegisterIfAbsent(kt.DSA)
		if kt.AddressDeriver != nil {
			addressderive.Register(kt.KeyType, kt.AddressDeriver)
		}
	}
	if r.Metadata != nil {
		algorithm.RegisterMetadata(r.Metadata)
	}
	for _, fn := range r.Extra {
		fn()
	}
}
