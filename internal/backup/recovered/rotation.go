// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package recovered

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const (
	rotationNewSuffix = ".new"
	rotationOldSuffix = ".old"
)

// RotationTargets validates published recovered batches, reconciles exact
// artifacts left by an interrupted passphrase rotation, and returns the
// encrypted files that must be re-encrypted.
//
// A canonical file is restored from its .old or .new sibling only when that
// sibling validates under masterKey. Unknown batch state and non-regular
// artifacts fail closed. Unpublished StagingDirPrefix directories are ignored.
// RotationTarget is one file a passphrase rotation must re-encrypt, together
// with the object it holds. Rotation changes the key, never the identity, so
// the context travels with the path rather than being re-derived downstream.
type RotationTarget struct {
	Path    string
	Context crypto.ObjectContext
}

func RotationTargets(paths storepaths.Paths, identityID string, masterKey []byte) ([]RotationTarget, error) {
	root := paths.RecoveredRootDir(identityID)
	rootInfo, err := os.Lstat(root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect recovered batch root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return nil, fmt.Errorf("recovered batch root is not a regular directory: %s", root)
	}

	batchDirs, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("scan recovered batch root: %w", err)
	}
	var targets []RotationTarget
	for _, batchDirEntry := range batchDirs {
		restoreID := batchDirEntry.Name()
		if strings.HasPrefix(restoreID, StagingDirPrefix) {
			continue
		}
		if err := ValidateRestoreID(restoreID); err != nil {
			return nil, fmt.Errorf("unexpected recovered batch directory %q: %w", restoreID, err)
		}
		batchDir := paths.RecoveredBatchDir(identityID, restoreID)
		if err := requireRegularDirectory(batchDir); err != nil {
			return nil, err
		}

		batchTargets, err := rotationTargetsForBatch(paths, identityID, restoreID, masterKey)
		if err != nil {
			return nil, err
		}
		targets = append(targets, batchTargets...)
	}
	return targets, nil
}

func rotationTargetsForBatch(
	paths storepaths.Paths,
	identityID, restoreID string,
	masterKey []byte,
) ([]RotationTarget, error) {
	batchDir := paths.RecoveredBatchDir(identityID, restoreID)
	metadataPath := paths.RecoveredBatchMetadataPath(identityID, restoreID)
	metadataName := filepath.Base(metadataPath)
	children, err := os.ReadDir(batchDir)
	if err != nil {
		return nil, fmt.Errorf("scan recovered batch %s: %w", restoreID, err)
	}
	for _, child := range children {
		switch child.Name() {
		case metadataName, metadataName + rotationNewSuffix, metadataName + rotationOldSuffix, entriesDirectoryName:
		default:
			return nil, fmt.Errorf(
				"recovered batch %s contains unsupported state %q; resolve it before passphrase rotation",
				restoreID,
				child.Name(),
			)
		}
	}

	if err := reconcileRotationFile(metadataPath, func(candidate string) error {
		_, err := loadBatchAt(candidate, restoreID, masterKey)
		return err
	}); err != nil {
		return nil, fmt.Errorf("reconcile recovered batch %s metadata: %w", restoreID, err)
	}
	batch, err := loadBatchAt(metadataPath, restoreID, masterKey)
	if err != nil {
		return nil, fmt.Errorf("validate recovered batch %s before passphrase rotation: %w", restoreID, err)
	}

	entriesDir := paths.RecoveredBatchEntriesDir(identityID, restoreID)
	if err := requireRegularDirectory(entriesDir); err != nil {
		return nil, fmt.Errorf("inspect recovered entries for %s: %w", restoreID, err)
	}
	entryFiles, err := os.ReadDir(entriesDir)
	if err != nil {
		return nil, fmt.Errorf("scan recovered entries for %s: %w", restoreID, err)
	}
	allowed := make(map[string]struct{}, len(batch.Entries)*3)
	for _, meta := range batch.Entries {
		allowed[meta.EntryFile] = struct{}{}
		allowed[meta.EntryFile+rotationNewSuffix] = struct{}{}
		allowed[meta.EntryFile+rotationOldSuffix] = struct{}{}
	}
	for _, entryFile := range entryFiles {
		if _, ok := allowed[entryFile.Name()]; !ok {
			return nil, fmt.Errorf(
				"recovered batch %s contains unexpected entry file %q",
				restoreID,
				entryFile.Name(),
			)
		}
	}

	targets := make([]RotationTarget, 0, len(batch.Entries)+1)
	targets = append(targets, RotationTarget{
		Path:    metadataPath,
		Context: crypto.RecoveredBatchContext(restoreID),
	})
	for _, meta := range batch.Entries {
		entryPath := filepath.Join(entriesDir, meta.EntryFile)
		if err := reconcileRotationFile(entryPath, func(candidate string) error {
			entry, err := loadEntryAt(candidate, restoreID, meta, masterKey)
			if entry != nil {
				entry.ZeroSecrets()
			}
			return err
		}); err != nil {
			return nil, fmt.Errorf("reconcile recovered entry %s/%s: %w", restoreID, meta.Selector, err)
		}
		targets = append(targets, RotationTarget{
			Path:    entryPath,
			Context: crypto.RecoveredEntryContext(restoreID, meta.Selector),
		})
	}
	return targets, nil
}

func reconcileRotationFile(path string, validate func(string) error) error {
	artifacts := []string{path + rotationOldSuffix, path + rotationNewSuffix}
	for _, artifact := range artifacts {
		if err := validateRotationArtifactShape(artifact); err != nil {
			return err
		}
	}

	if err := validate(path); err == nil {
		return removeRotationArtifacts(path)
	} else {
		canonicalErr := err
		for _, artifact := range artifacts {
			if _, statErr := os.Lstat(artifact); os.IsNotExist(statErr) {
				continue
			} else if statErr != nil {
				return fmt.Errorf("inspect rotation artifact %s: %w", artifact, statErr)
			}
			if err := validate(artifact); err != nil {
				continue
			}
			if err := os.Rename(artifact, path); err != nil {
				return fmt.Errorf("restore %s from %s: %w", path, artifact, err)
			}
			if err := removeRotationArtifacts(path); err != nil {
				return err
			}
			if err := syncDirectory(filepath.Dir(path)); err != nil {
				return fmt.Errorf("sync reconciled rotation directory: %w", err)
			}
			if err := validate(path); err != nil {
				return fmt.Errorf("validate reconciled file %s: %w", path, err)
			}
			return nil
		}
		return fmt.Errorf(
			"canonical file is not valid under the current master key and no rotation artifact can restore it: %w",
			canonicalErr,
		)
	}
}

func validateRotationArtifactShape(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect rotation artifact %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("rotation artifact is not a regular file: %s", path)
	}
	return nil
}

func removeRotationArtifacts(path string) error {
	removed := false
	for _, suffix := range []string{rotationOldSuffix, rotationNewSuffix} {
		artifact := path + suffix
		if err := os.Remove(artifact); err == nil {
			removed = true
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("remove stale rotation artifact %s: %w", artifact, err)
		}
	}
	if removed {
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			return fmt.Errorf("sync rotation artifact cleanup: %w", err)
		}
	}
	return nil
}

func requireRegularDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect directory %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("path is not a regular directory: %s", path)
	}
	return nil
}
