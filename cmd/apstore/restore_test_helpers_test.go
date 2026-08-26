// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
)

func restoreContextForTest() backup.Restorer {
	paths := keystorePaths()
	if bound, err := genstoretest.BindDefault(paths); err == nil {
		paths = bound
	}
	return backup.NewRestorer(paths).WithLogger(logInfof).WithOverwrite(true)
}

func restoreKey(keysDir, address string, kr *crypto.Keyring, exportPassphrase []byte) (string, error) {
	return restoreContextForTest().RestoreKey(keysDir, address, kr, exportPassphrase)
}

func restoreKeyMetadata(keyJSON []byte) (keyType string, address string, hasLogicSigBytecode bool, err error) {
	return backup.RestoreKeyMetadata(keyJSON)
}
