// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import "github.com/aplane-algo/aplane/internal/backup"

func restoreContextForTest() backup.Restorer {
	return backup.NewRestorer(keystorePaths(), productIdentityID()).WithLogger(logInfof).WithOverwrite(true)
}

func restoreKey(keysDir, address string, masterKey, exportPassphrase []byte) (string, error) {
	return restoreContextForTest().RestoreKey(keysDir, address, masterKey, exportPassphrase)
}

func restoreKeyMetadata(keyJSON []byte) (keyType string, address string, hasLogicSigBytecode bool, err error) {
	return backup.RestoreKeyMetadata(keyJSON)
}

func restoreTemplate(templateYAML []byte, keyType, tmplType string, masterKey []byte) error {
	return restoreContextForTest().RestoreTemplate(templateYAML, keyType, tmplType, masterKey)
}
