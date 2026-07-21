// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerreg registers the signer-side Ed25519 components: the
// signing provider, key generators, and mnemonic handler. Only signer
// binaries (and their tests) import it; clients use the parent ed25519
// package's RegisterClient, which registers metadata only.
package signerreg

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/mnemonic"
	ed25519 "github.com/aplane-algo/aplane/internal/signing/ed25519"
)

var registerSignerOnce sync.Once

// RegisterSigner registers all Ed25519 components with their respective registries.
// This is idempotent and safe to call multiple times.
//
// Registration includes RegisterClient plus:
// - Signing provider for transaction signing
// - Key generator for key creation
// - Mnemonic handler for Algorand mnemonic handling
func RegisterSigner() {
	registerSignerOnce.Do(func() {
		ed25519.RegisterClient()

		// Signing provider for transaction signing
		RegisterProvider()

		// Key generator for creating new keys
		keygen.RegisterEd25519Generator()
		// Mnemonic handler for Algorand mnemonic handling
		mnemonic.RegisterEd25519Handler()
	})
}
