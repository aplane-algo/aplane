// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/noderole"
)

func cmdRebuild(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apstore rebuild <archive-path> [--role signer|attestor] [--address ADDRESS ...]")
	}
	source := args[0]
	var addresses []string
	var role noderole.Role
	var roleSet bool
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--address":
			if i+1 >= len(args) {
				return fmt.Errorf("usage: apstore rebuild <archive-path> [--role signer|attestor] [--address ADDRESS ...]")
			}
			addresses = append(addresses, args[i+1])
			i++
		case "--role":
			if i+1 >= len(args) {
				return fmt.Errorf("usage: apstore rebuild <archive-path> [--role signer|attestor] [--address ADDRESS ...]")
			}
			parsed, err := noderole.ParseRole(args[i+1])
			if err != nil {
				return fmt.Errorf("invalid rebuild role: %w", err)
			}
			role = parsed
			roleSet = true
			i++
		default:
			return fmt.Errorf("unknown rebuild option: %s", args[i])
		}
	}
	return cmdRebuildFromBackup(source, addresses, role, roleSet)
}

func cmdRebuildFromBackup(source string, addresses []string, explicitRole noderole.Role, explicitRoleSet bool) error {
	identityDir := keystorePaths().IdentityDir(productIdentityID())
	if _, err := os.Stat(identityDir); err == nil {
		return fmt.Errorf("rebuild requires a missing identity directory; move or archive the existing directory first: %s", identityDir)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to inspect identity directory: %w", err)
	}
	if !backup.IsArchivePath(source) {
		return fmt.Errorf("rebuild source must end in .tar.gz or .tgz: %s", source)
	}
	if _, err := os.Stat(source); os.IsNotExist(err) {
		return fmt.Errorf("backup not found: %s", source)
	} else if err != nil {
		return fmt.Errorf("failed to inspect backup: %w", err)
	}

	sourceRoot, cleanup, err := prepareBackupSource(source)
	if err != nil {
		return err
	}
	defer cleanup()

	logWarnf("REBUILD RECOVERY BYPASSES APSIGNER")
	logWarnf("authorization, audit logging, rate limiting, runtime reload, and admin IPC policy are not used")
	logWarnf("rebuild has no durable audit log; capture terminal output externally if needed")

	nodeRole, err := selectRebuildNodeRole(sourceRoot, explicitRole, explicitRoleSet)
	if err != nil {
		return err
	}

	fmt.Print("Enter export passphrase (to decrypt backup files): ")
	exportPassphrase, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %w", err)
	}
	defer crypto.ZeroBytes(exportPassphrase)
	fmt.Println()

	if err := verifyRebuildSource(sourceRoot, exportPassphrase); err != nil {
		return err
	}

	fmt.Print("Enter new store passphrase: ")
	storePassphrase, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %w", err)
	}
	defer crypto.ZeroBytes(storePassphrase)
	fmt.Println()

	fmt.Print("Confirm passphrase: ")
	confirmPassphrase, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %w", err)
	}
	defer crypto.ZeroBytes(confirmPassphrase)
	fmt.Println()

	if !bytes.Equal(storePassphrase, confirmPassphrase) {
		return fmt.Errorf("passphrases do not match")
	}

	_, masterKey, err := crypto.CreateKeystoreMetadata(keystorePaths().KeystoreMetadataDir(productIdentityID()), storePassphrase)
	if err != nil {
		return fmt.Errorf("failed to create keystore metadata: %w", err)
	}
	defer crypto.ZeroBytes(masterKey)

	if err := initializeRebuildNodeRole(nodeRole, masterKey); err != nil {
		return err
	}
	if err := rebuildRestoreKeys(sourceRoot, addresses, nodeRole, masterKey, exportPassphrase); err != nil {
		return err
	}
	logInfof("rebuild complete: %s", identityDir)
	return nil
}

func selectRebuildNodeRole(sourceRoot string, explicitRole noderole.Role, explicitRoleSet bool) (noderole.Role, error) {
	manifest, ok, err := backup.ReadManifest(sourceRoot)
	if err != nil {
		return "", err
	}
	if ok {
		manifestRole, err := noderole.ParseRole(manifest.SourceNodeRole)
		if err != nil {
			return "", err
		}
		if explicitRoleSet {
			if explicitRole != manifestRole {
				logWarnf("backup manifest source node role is %q; rebuilding destination as %q from --role", manifestRole, explicitRole)
			} else {
				logInfof("rebuild node role: %s (--role matches backup manifest)", explicitRole)
			}
			return explicitRole, nil
		}
		logInfof("rebuild node role: %s (from backup manifest; pass --role to override)", manifestRole)
		return manifestRole, nil
	}
	if explicitRoleSet {
		logInfof("rebuild node role: %s (from --role; backup manifest has no source role metadata)", explicitRole)
		return explicitRole, nil
	}
	role := noderole.DefaultRole()
	logWarnf("backup manifest has no source node role metadata; defaulting rebuild destination role to %q (use --role sentry for attestor backups)", role)
	return role, nil
}

func verifyRebuildSource(sourceRoot string, exportPassphrase []byte) error {
	report, err := backup.DeepVerifyBackup(sourceRoot, string(exportPassphrase))
	if err != nil {
		return fmt.Errorf("failed to verify rebuild backup: %w", err)
	}
	if report.FailedFiles > 0 {
		return fmt.Errorf("failed to verify rebuild backup: %d file(s) failed deep verification", report.FailedFiles)
	}
	return nil
}

func initializeRebuildNodeRole(role noderole.Role, masterKey []byte) error {
	roleBytes, _, err := noderole.SaveInitial(keystorePaths(), role, time.Now())
	if err != nil {
		return fmt.Errorf("failed to create node role: %w", err)
	}
	if err := noderole.SaveIdentitySidecarWithMasterKey(keystorePaths(), productIdentityID(), roleBytes, masterKey, time.Now()); err != nil {
		return fmt.Errorf("failed to create node role integrity sidecar: %w", err)
	}
	return nil
}

func rebuildRestoreKeys(sourceRoot string, addresses []string, role noderole.Role, masterKey, exportPassphrase []byte) error {
	keysDir := resolveBackupKeysDir(sourceRoot)
	if len(addresses) == 0 {
		var err error
		addresses, err = backup.ScanBackupFiles(keysDir)
		if err != nil {
			return err
		}
	}
	if len(addresses) == 0 {
		return fmt.Errorf("no .apb files found in backup: %s", sourceRoot)
	}

	restored := 0
	for _, address := range addresses {
		keyType, err := backup.NewRestorer(keystorePaths(), productIdentityID()).
			WithNodeRole(role).
			WithLogger(logInfof).
			RestoreKey(keysDir, address, masterKey, exportPassphrase)
		if err != nil {
			return fmt.Errorf("failed to rebuild %s: %w", address, err)
		}
		label := address
		if keyType != "" {
			label += fmt.Sprintf(" (%s)", keyType)
		}
		logInfof("rebuilt: %s", label)
		restored++
	}
	logInfof("successfully rebuilt %d key(s)", restored)
	return nil
}
