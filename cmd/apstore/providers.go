// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	ed25519signerreg "github.com/aplane-algo/aplane/internal/signing/ed25519/signerreg"
	nativefalconsignerreg "github.com/aplane-algo/aplane/internal/signing/falcon1024/signerreg"
	lsigsignerreg "github.com/aplane-algo/aplane/lsig/signerreg"
)

// RegisterProviders registers all DSA providers for SignerStore.
// This must be called before using any key processing operations.
func RegisterProviders() {
	lsigsignerreg.RegisterSigner()    // Built-in LogicSig providers
	ed25519signerreg.RegisterSigner() // All Ed25519 components
	nativefalconsignerreg.RegisterSigner()
}
