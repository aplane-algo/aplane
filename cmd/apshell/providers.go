// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	ed25519 "github.com/aplane-algo/aplane/internal/signing/ed25519"
	"github.com/aplane-algo/aplane/lsig"
)

// RegisterProviders registers all DSA providers for the apshell CLI.
// This must be called before using any key processing or signing operations.
func RegisterProviders() {
	lsig.RegisterAll()    // All Falcon + LogicSig templates
	ed25519.RegisterAll() // All Ed25519 components
}
