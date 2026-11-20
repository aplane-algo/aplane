// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"
	"github.com/aplane-algo/aplane/internal/stagetable"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const rebuildUsage = "usage: apstore rebuild <archive-path> [--role signer|cosigner] [--address ADDRESS ...]"

func cmdRebuild(args []string) error {
	if len(args) == 0 {
		return usageErrorf("%s", rebuildUsage)
	}
	source := args[0]
	var addresses []string
	var role noderole.Role
	var roleSet bool
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--address":
			if i+1 >= len(args) {
				return usageErrorf("%s", rebuildUsage)
			}
			addresses = append(addresses, args[i+1])
			i++
		case "--role":
			if i+1 >= len(args) {
				return usageErrorf("%s", rebuildUsage)
			}
			parsed, err := noderole.ParseRole(args[i+1])
			if err != nil {
				return usageErrorf("invalid rebuild role: %v", err)
			}
			role = parsed
			roleSet = true
			i++
		default:
			return usageErrorf("unknown rebuild option: %s", args[i])
		}
	}
	return cmdRebuildFromBackup(source, addresses, role, roleSet)
}

func cmdRebuildFromBackup(source string, addresses []string, explicitRole noderole.Role, explicitRoleSet bool) error {
	identityDir := keystorePaths().ProductDir()
	if _, err := os.Stat(identityDir); err == nil {
		return fmt.Errorf("rebuild requires a missing identity directory; move or archive the existing directory first: %s", identityDir)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to inspect identity directory: %w", err)
	}
	// The node role file sits at the data root, outside the identity
	// directory, and rebuild writes a fresh one. Refuse a leftover here, not
	// after every prompt and the deep verify.
	nodeRolePath := keystorePaths().NodeRolePath()
	if _, err := os.Lstat(nodeRolePath); err == nil {
		return fmt.Errorf("rebuild requires a missing node role file; move or archive it with the identity directory first: %s", nodeRolePath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to inspect node role file: %w", err)
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

	set, err := loadRebuildSet(sourceRoot, addresses, exportPassphrase, nodeRole)
	if err != nil {
		return err
	}
	defer set.ZeroSecrets()

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

	// Rebuild stages the complete first generation and publishes one root that
	// commits its fresh key authority and generation selection together.
	kr, err := crypto.NewKeyring()
	if err != nil {
		return fmt.Errorf("failed to create store keyring: %w", err)
	}
	defer kr.Zero()

	roleBytes, err := noderole.SaveInitial(keystorePaths(), nodeRole, time.Now())
	if err != nil {
		return fmt.Errorf("failed to create node role: %w", err)
	}
	// Until the mint may have committed, the node role file belongs to this
	// attempt alone: remove it on failure so a retry is not refused by it.
	keepNodeRole := false
	defer func() {
		if keepNodeRole {
			return
		}
		if err := os.Remove(nodeRolePath); err != nil && !os.IsNotExist(err) {
			logWarnf("failed to remove the node role file this rebuild wrote; remove it before retrying: %v", err)
		}
	}()
	generationID, err := genstore.NewGenerationID(time.Now())
	if err != nil {
		return err
	}
	// Validate the complete rebuilt store before committing it: once a
	// generation exists, rebuild refuses to run again, so an invalid commit
	// could only be repaired by hand.
	if _, err := genstore.Mint(keystorePaths(), genstore.MintRequest{
		GenerationID:      generationID,
		FirstGeneration:   true,
		InitialPassphrase: storePassphrase,
		Operation:         "store-rebuild",
		OperationID:       "rebuild-" + generationID,
		CreatedAt:         time.Now(),
		Integrity:         kr,
		ValidateCandidate: func(staged storepaths.GenPaths) error {
			return storevalidate.FirstGeneration(storeinit.FirstGenerationCandidate{
				Paths: keystorePaths(), Staged: staged, Keyring: kr, Role: nodeRole, DataDir: dataDirectory,
			})
		},
		Apply: func(staged storepaths.GenPaths) error {
			if err := noderole.SaveGenerationSidecarWithKeyring(
				staged,
				roleBytes,
				kr,
				time.Now(),
			); err != nil {
				return fmt.Errorf("failed to create node role integrity sidecar: %w", err)
			}
			if err := policy.WriteEmbeddedDefault(staged, nodeRole, kr, time.Now()); err != nil {
				return fmt.Errorf("failed to create default policy: %w", err)
			}
			return backup.ApplyRebuildSet(staged, nodeRole, set, kr)
		},
	}); err != nil {
		if genstore.RootCommitUncertain(err) {
			// The root may select the new generation, which needs the
			// node role file.
			keepNodeRole = true
			return fmt.Errorf("rebuild may have committed; unlock the signer to check: %w", err)
		}
		return fmt.Errorf("rebuild failed; nothing was committed: %w", err)
	}
	keepNodeRole = true
	backup.PublishRotatingHints(stagetable.NewStore(keystorePaths()), set.StageHints(), logWarnf)
	for _, entry := range set.Entries {
		label := fmt.Sprintf("rebuilt: %s (%s)", entry.Selector(), entry.KeyType())
		if entry.Policy != nil {
			label += " with its policy"
		}
		logInfof("%s", label)
	}
	logInfof("rebuild complete: %s; %d key(s) rebuilt, %d skipped", identityDir, len(set.Entries), len(set.Skipped))
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

// loadRebuildSet admits the selected credentials for role before any store
// passphrase is asked for, and reports each one the rebuild skips. A rebuild
// that names a skipped credential, or has nothing left to rebuild, is
// refused.
func loadRebuildSet(sourceRoot string, addresses []string, exportPassphrase []byte, role noderole.Role) (*backup.RestoreSet, error) {
	set, err := backup.LoadRebuildSet(sourceRoot, addresses, exportPassphrase, role)
	var refusal *backup.SkipRefusalError
	switch {
	case errors.As(err, &refusal):
		reportRebuildSkips(refusal.Skipped)
		return nil, fmt.Errorf("rebuild refused: %w", err)
	case err != nil:
		return nil, fmt.Errorf("failed to verify rebuild backup: %w", err)
	}
	reportRebuildSkips(set.Skipped)
	return set, nil
}

func reportRebuildSkips(skipped []backup.SkippedEntry) {
	for _, entry := range skipped {
		logWarnf("skipping %s: %s", entry.Selector, entry.Reason)
	}
}
