// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
)

// testIdentityBuildOptions mirrors the startup options main() derives from the
// server's resolved state, for tests that wire identity runtimes directly.
func testIdentityBuildOptions(fs *Signer) signerstartup.IdentityBuildOptions {
	return signerstartup.IdentityBuildOptions{
		DataDir:  fs.dataDir,
		KeyPaths: fs.keyPaths,
		Config:   fs.config,
	}
}
