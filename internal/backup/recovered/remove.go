// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package recovered

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

// RemoveBatch atomically removes one published batch from recovered inventory.
// A crash after the namespace rename can leave only an ignored staging
// tombstone, never a partially visible published batch.
func RemoveBatch(paths storepaths.Paths, identityID, restoreID string) error {
	if err := ValidateRestoreID(restoreID); err != nil {
		return err
	}
	root := paths.RecoveredRootDir(identityID)
	if err := requireRegularDirectory(root); err != nil {
		return err
	}
	batchDir := paths.RecoveredBatchDir(identityID, restoreID)
	if err := requireRegularDirectory(batchDir); err != nil {
		return err
	}
	tombstone := filepath.Join(root, StagingDirPrefix+"completed-"+restoreID)
	if _, err := os.Lstat(tombstone); err == nil {
		return fmt.Errorf("recovered completion tombstone already exists: %s", tombstone)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect recovered completion tombstone: %w", err)
	}
	if err := os.Rename(batchDir, tombstone); err != nil {
		return fmt.Errorf("remove recovered batch from inventory: %w", err)
	}
	if err := syncDirectory(root); err != nil {
		renameErr := os.Rename(tombstone, batchDir)
		_ = syncDirectory(root)
		if renameErr != nil {
			return fmt.Errorf("sync recovered batch removal: %w (restore namespace: %v)", err, renameErr)
		}
		return fmt.Errorf("sync recovered batch removal: %w", err)
	}

	// The durable rename is the logical removal. Cleanup is best-effort because
	// List and rotation deliberately ignore staging-prefixed leftovers.
	if err := os.RemoveAll(tombstone); err == nil {
		_ = syncDirectory(root)
	}
	return nil
}
