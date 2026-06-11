// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package dsafamily holds the family-neutral pieces a LogicSig DSA family
// needs: the shared key generator and the registration descriptors that fan a
// family's capabilities out to the process-global registries. A family
// declares one ClientRegistration (and, in its signerreg package, one
// SignerRegistration) instead of hand-writing per-registry calls, so partial
// registration is not representable.
//
// Product-level visibility (keytypecatalog entries and availability gating)
// intentionally stays in the lsig root aggregator: which compiled key types
// are exposed is a product decision, not a family one.
package dsafamily

import (
	"github.com/aplane-algo/aplane/internal/addressderive"
	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/mnemonic"
	"github.com/aplane-algo/aplane/internal/signing"
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

// GeneratorSpec describes one key generator a family registers, together with
// the mnemonic handler its seed derivation routes through.
type GeneratorSpec struct {
	// Family is the generator registry key; the shared generator resolves its
	// mnemonic handler by this name, so Mnemonic must be registered under it.
	Family string
	// Ops maps each accepted key type (and the family name, when accepted) to
	// its keypair-generation ops.
	Ops map[string]LogicSigKeygenOps
	// Mnemonic is the handler registered for Family; nil skips mnemonic
	// registration (the generator then rejects mnemonic-based generation).
	Mnemonic mnemonic.Handler
}

// SignerRegistration is the signer-side half of a family's capabilities.
type SignerRegistration struct {
	// RegisterClient is the family's once-guarded client registration; it
	// runs first so signer binaries always carry the client-safe surface.
	RegisterClient func()
	// SigningProvider is the family's transaction-signing provider; nil for
	// pure-LogicSig families that sign via component flows.
	SigningProvider signing.Provider
	// Generators lists the key generators the family registers.
	Generators []GeneratorSpec
	// Extra holds family-specific signer-side registrations that have no
	// generic slot (e.g. sentry component generators and validators).
	Extra []func()
}

// RegisterSigner fans a family's signer-side capabilities out to the global
// registries. Callers guard idempotency with their own sync.Once, matching
// the per-family RegisterSigner convention.
func RegisterSigner(r SignerRegistration) {
	if r.RegisterClient != nil {
		r.RegisterClient()
	}
	if r.SigningProvider != nil {
		signing.Register(r.SigningProvider)
	}
	for _, g := range r.Generators {
		keygen.Register(NewLogicSigGenerator(g.Family, g.Ops))
		if g.Mnemonic != nil {
			mnemonic.Register(g.Mnemonic)
		}
	}
	for _, fn := range r.Extra {
		fn()
	}
}
