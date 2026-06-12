// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"github.com/aplane-algo/aplane/internal/apshellcli"
	ed25519signerreg "github.com/aplane-algo/aplane/internal/signing/ed25519/signerreg"
	lsigsignerreg "github.com/aplane-algo/aplane/lsig/signerreg"
)

// RegisterProviders registers the signer-admin provider set used by the
// embedded admin surface. The console still talks to apsigner over the
// existing admin protocol; these registrations support local UI metadata and
// template handling just as apadmin does.
func RegisterProviders() {
	apshellcli.RegisterProviders()
	lsigsignerreg.RegisterSigner()
	ed25519signerreg.RegisterSigner()
}
