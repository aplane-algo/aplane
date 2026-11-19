// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/noderole"
)

// restoreKey restores one backup entry into the test store's active
// generation, as a rebuild does.
func restoreKey(keysDir, address string, kr *crypto.Keyring, exportPassphrase []byte) (string, error) {
	paths, err := genstoretest.BindDefault(keystorePaths())
	if err != nil {
		return "", err
	}
	active, err := genstore.Resolve(paths)
	if err != nil {
		return "", err
	}
	return backup.RestoreForRebuild(active, noderole.DefaultRole(), keysDir, address, kr, exportPassphrase, logInfof)
}
