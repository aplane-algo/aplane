// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import "github.com/aplane-algo/aplane/internal/backup"

func restoreContext() backup.Restorer {
	return backup.NewRestorer(keystorePaths(), productIdentityID()).WithLogger(logInfof)
}

func resolveBackupKeysDir(source string) string {
	return backup.ResolveBackupKeysDir(source)
}

func restoreKey(keysDir, address string, masterKey, exportPassphrase []byte) (string, error) {
	return restoreContext().RestoreKey(keysDir, address, masterKey, exportPassphrase)
}

func restoreKeyMetadata(keyJSON []byte) (keyType string, address string, hasLogicSigBytecode bool, err error) {
	return backup.RestoreKeyMetadata(keyJSON)
}

func restoreTemplate(templateYAML []byte, keyType, tmplType string, masterKey []byte) error {
	return restoreContext().RestoreTemplate(templateYAML, keyType, tmplType, masterKey)
}

func prepareBackupSource(source string) (string, func(), error) {
	return backup.PrepareRestoreSource(source)
}
