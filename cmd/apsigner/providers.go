// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	ed25519 "github.com/aplane-algo/aplane/internal/signing/ed25519"
	lsigsignerreg "github.com/aplane-algo/aplane/lsig/signerreg"
)

// RegisterProviders registers all DSA providers for apsigner.
// This must be called before using any signing or key operations.
func RegisterProviders() {
	// All LogicSig providers (Falcon-1024, etc.)
	lsigsignerreg.RegisterSigner()

	// Ed25519 native signatures
	ed25519.RegisterSigner()
}
