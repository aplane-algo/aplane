// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"os"
	"strings"

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

	report, err := backup.DeepVerifyBackupBytes(backupPath, passphrase)
	crypto.ZeroBytes(passphrase)
	if err != nil {
		return codedError{code: "verification_failed", message: err.Error()}
	}

	logInfof("found %d key file(s)", len(report.Verified)+len(report.Skipped))
	for _, result := range report.Verified {
		logInfof("  %s.apb (%s, decrypts OK)", result.Address, result.KeyType)
		if result.HasPolicy {
			logInfof("  policies/%s.apb (policy, decrypts OK)", result.Address)
		}
		if len(result.SourceTokens) > 0 {
			logInfof("  source_tokens/%s.apb (source tokens for %s, decrypts OK)", result.Address, strings.Join(result.SourceTokens, ", "))
		}
	}
	for _, skipped := range report.Skipped {
		logErrorf("  %s.apb - restore would skip it: %s", skipped.Selector, skipped.Reason)
	}
	if err := report.Incomplete(); err != nil {
		return codedError{code: "verification_failed", message: err.Error()}
	}
	logInfof("all keys valid and decryptable")
	return nil
}
