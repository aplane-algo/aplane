// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package ed25519 registers client-safe Ed25519 key-type metadata. It owns
// no key material and performs no signing: the signing provider, key
// generators, and mnemonic handler live in the signerreg subpackage so client
// binaries that only need catalog metadata and address derivation do not
// link signer-side code.
package ed25519

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/addressderive"
	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
)

var registerClientOnce sync.Once

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
