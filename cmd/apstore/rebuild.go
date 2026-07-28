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
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func cmdRebuild(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apstore rebuild <archive-path> [--role signer|sentry] [--address ADDRESS ...]")
	}
	source := args[0]
	var addresses []string
	var role noderole.Role
	var roleSet bool
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--address":
			if i+1 >= len(args) {
				return fmt.Errorf("usage: apstore rebuild <archive-path> [--role signer|sentry] [--address ADDRESS ...]")
			}
			addresses = append(addresses, args[i+1])
			i++
		case "--role":
			if i+1 >= len(args) {
				return fmt.Errorf("usage: apstore rebuild <archive-path> [--role signer|sentry] [--address ADDRESS ...]")
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

	fmt.Print("Enter export passphrase (to decrypt backup files): ")
	exportPassphrase, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %w", err)
	}
	defer crypto.ZeroBytes(exportPassphrase)
	fmt.Println()

	// The source role lives in the sealed manifest, so role selection
	// follows the passphrase prompt.
	nodeRole, err := selectRebuildNodeRole(sourceRoot, exportPassphrase, explicitRole, explicitRoleSet)
	if err != nil {
		return err
	}

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

	// Rebuilt stores use generation-based active storage: version-3
	// keystore metadata plus the restored keys committed as the first
	// generation behind a durable CURRENT flip.
	_, masterKey, err := crypto.CreateKeystoreMetadata(keystorePaths().KeystoreMetadataDir(productIdentityID()), storePassphrase)
	if err != nil {
		return fmt.Errorf("failed to create keystore metadata: %w", err)
	}
	defer crypto.ZeroBytes(masterKey)

	if err := initializeRebuildNodeRole(nodeRole, masterKey); err != nil {
		return err
	}
	generationID, err := genstore.NewGenerationID(time.Now())
	if err != nil {
		return err
	}
	if _, err := genstore.Mint(keystorePaths(), productIdentityID(), genstore.MintRequest{
		GenerationID:    generationID,
		FirstGeneration: true,
		Operation:       "store-rebuild",
		OperationID:     "rebuild-" + generationID,
		CreatedAt:       time.Now(),
		Apply: func(staged storepaths.GenPaths) error {
			return rebuildRestoreKeys(sourceRoot, addresses, nodeRole, masterKey, exportPassphrase, staged)
		},
	}); err != nil {
		return fmt.Errorf("rebuild failed; nothing was committed: %w", err)
	}
	logInfof("rebuild complete: %s", identityDir)
	return nil
}

// selectRebuildNodeRole reads the destination role default from the archive's
// sealed manifest. Every readable archive carries one, so the role is always
// authenticated; --role remains the explicit override.
func selectRebuildNodeRole(
	sourceRoot string,
	exportPassphrase []byte,
	explicitRole noderole.Role,
	explicitRoleSet bool,
) (noderole.Role, error) {
	manifest, err := backup.OpenSealedManifest(sourceRoot, exportPassphrase)
	if err != nil {
		return "", err
	}
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

func rebuildRestoreKeys(sourceRoot string, addresses []string, role noderole.Role, masterKey, exportPassphrase []byte, staged storepaths.GenPaths) error {
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
			WithActiveNamespace(staged).
			RestoreActiveForRebuild(keysDir, address, masterKey, exportPassphrase)
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
