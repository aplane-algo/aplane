// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	ed25519 "github.com/aplane-algo/aplane/internal/signing/ed25519"
	lsigsignerreg "github.com/aplane-algo/aplane/lsig/signerreg"
)

// RegisterProviders mirrors the provider set cmd/apsigner ships with, for
// tests that exercise full key flows. Production registration lives in the
// binary so embedders choose their own provider set.
func RegisterProviders() {
	lsigsignerreg.RegisterSigner()
	ed25519.RegisterSigner()
}
