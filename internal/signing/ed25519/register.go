// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package ed25519

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/addressderive"
	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/mnemonic"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
)

var (
	registerClientOnce sync.Once
	registerSignerOnce sync.Once
)

// RegisterClient registers Ed25519 client-safe metadata and address derivation.
// This is idempotent and safe to call multiple times.
//
// Registration includes:
// - Algorithm metadata (signature size, mnemonic word count, display color)
// - Address deriver for Ed25519 public key to Algorand address
func RegisterClient() {
	registerClientOnce.Do(func() {
		keytypecatalog.Register(keytypecatalog.Entry{
			KeyType:      "ed25519",
			Family:       "ed25519",
			Availability: keytypecatalog.AvailabilityDefaultEnabled,
		})

		// Algorithm metadata (display color, signature size, etc.)
		algorithm.RegisterEd25519Metadata()

		// Address deriver for Ed25519 public key to Algorand address
		addressderive.RegisterEd25519()
	})
}

// RegisterSigner registers all Ed25519 components with their respective registries.
// This is idempotent and safe to call multiple times.
//
// Registration includes RegisterClient plus:
// - Signing provider for transaction signing
// - Key generator for key creation
// - Mnemonic handler for Algorand mnemonic handling
func RegisterSigner() {
	registerSignerOnce.Do(func() {
		RegisterClient()

		// Signing provider for transaction signing
		RegisterProvider()

		// Key generator for creating new keys
		keygen.RegisterEd25519Generator()
		keygen.RegisterAttestorEd25519Generator()
		keytypecatalog.Register(keytypecatalog.Entry{
			KeyType:      keytypes.AttestorComponentEd25519V1,
			Family:       "sentry-ed25519",
			Availability: keytypecatalog.AvailabilityDefaultEnabled,
		})

		// Mnemonic handler for Algorand mnemonic handling
		mnemonic.RegisterEd25519Handler()
	})
}
