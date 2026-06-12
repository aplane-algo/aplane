// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerreg holds the signer-side half of a LogicSig DSA family's
// capabilities: the shared key generator and the SignerRegistration
// descriptor that fans signing providers, key generators, and mnemonic
// handlers out to the process-global registries. Only signer binaries (and
// their tests) link this package; client-safe registration lives in the
// parent lsig/dsafamily package.
package signerreg

import (
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/mnemonic"
	"github.com/aplane-algo/aplane/internal/signing"
)

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
