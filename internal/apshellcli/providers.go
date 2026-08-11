// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	ed25519 "github.com/aplane-algo/aplane/internal/signing/ed25519"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/lsig"
)

// RegisterProviders registers client-safe provider metadata for the apshell CLI.
// Private-key signing, keygen, and mnemonic registries remain signer-side.
func RegisterProviders() {
	lsig.RegisterClient()
	ed25519.RegisterClient()
	nativefalcon.RegisterClient()
}
