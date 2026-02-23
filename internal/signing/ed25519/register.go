// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package ed25519

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/mnemonic"
	"github.com/aplane-algo/aplane/internal/util"
)

var registerAllOnce sync.Once

// RegisterAll registers all Ed25519 components with their respective registries.
// This is idempotent and safe to call multiple times.
//
// Registration includes:
// - Algorithm metadata (signature size, mnemonic word count, display color)
// - Signing provider for transaction signing
// - Key generator for key creation
// - Mnemonic handler for Algorand mnemonic handling
// - Key processors for key file processing and address derivation
func RegisterAll() {
	registerAllOnce.Do(func() {
		// Algorithm metadata (display color, signature size, etc.)
		algorithm.RegisterEd25519Metadata()

		// Signing provider for transaction signing
		RegisterProvider()

		// Key generator for creating new keys
		keygen.RegisterEd25519Generator()

		// Mnemonic handler for Algorand mnemonic handling
		mnemonic.RegisterEd25519Handler()

		// Address deriver for Ed25519 public key → Algorand address
		util.RegisterEd25519AddressDeriver()
	})
}
