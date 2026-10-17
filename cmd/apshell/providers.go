// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"github.com/aplane-algo/aplane/internal/apshellcli"
	"github.com/aplane-algo/aplane/lsig/clientreg"
)

// RegisterProviders registers the client-safe provider set for apshell:
// LogicSig metadata and derivation, then the native key types. Nothing here
// links key generation, mnemonics or signing; cmd/apshell/deps_test.go pins
// that boundary.
func RegisterProviders() {
	clientreg.RegisterClient()
	apshellcli.RegisterProviders()
}
