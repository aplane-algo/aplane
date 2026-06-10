// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
)

func cmdVerify(backupPath string) error {
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup not found: %s", backupPath)
	}
	sourceRoot, cleanup, err := prepareBackupSource(backupPath)
	if err != nil {
		return err
	}
	defer cleanup()

	return verifyDeep(sourceRoot)
}

func verifyDeep(backupPath string) error {
	logInfof("verification requires passphrase to decrypt keys")
	fmt.Print("Enter passphrase: ")

	passphrase, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %w", err)
	}
	fmt.Println()

	logInfof("verifying %s", backupPath)

	report, err := backup.DeepVerifyBackup(backupPath, string(passphrase))
	crypto.ZeroBytes(passphrase)
	if err != nil {
		return codedError{code: "verification_failed", message: err.Error()}
	}

	logInfof("found %d key file(s)", report.TotalFiles)

	for _, result := range report.Results {
		if result.Valid {
			logInfof("  %s (%s, decrypts OK)", result.FileName, displayKeyType(result.KeyType))
		} else {
			logErrorf("  %s - %s", result.FileName, result.Error)
		}
	}

	if report.FailedFiles == 0 {
		logInfof("all keys valid and decryptable")
	} else {
		logWarnf("%d file(s) failed validation", report.FailedFiles)
	}

	return nil
}
