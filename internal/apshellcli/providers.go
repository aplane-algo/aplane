// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	ed25519 "github.com/aplane-algo/aplane/internal/signing/ed25519"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

// RegisterProviders registers the native key types' client-safe metadata for
// the apshell CLI. Private-key signing, keygen, and mnemonic registries remain
// signer-side. LogicSig client registration (lsig/clientreg) is the binary's
// job, as signer-side registration is for the signer binaries, so shared code
// under internal/ never imports the lsig tree.
func RegisterProviders() {
	ed25519.RegisterClient()
	nativefalcon.RegisterClient()
}
