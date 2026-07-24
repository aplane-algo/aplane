// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package recovered

import (
	"fmt"
	"os"
	"strings"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

// IncompleteActivationIDs returns published batches with durable activation
// markers without decrypting or scanning active credentials.
func IncompleteActivationIDs(paths storepaths.Paths, identityID string) ([]string, error) {
	root := paths.RecoveredRootDir(identityID)
	info, err := os.Lstat(root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect recovered root for incomplete activation: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("recovered batch root is not a regular directory: %s", root)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("scan recovered root for incomplete activation: %w", err)
	}
	var restoreIDs []string
	for _, entry := range entries {
		restoreID := entry.Name()
		if strings.HasPrefix(restoreID, StagingDirPrefix) {
			continue
		}
		if err := ValidateRestoreID(restoreID); err != nil {
			return nil, fmt.Errorf("unexpected recovered batch directory %q: %w", restoreID, err)
		}
		if err := requireRegularDirectory(paths.RecoveredBatchDir(identityID, restoreID)); err != nil {
			return nil, err
		}
		activationDir := paths.RecoveredActivationDir(identityID, restoreID)
		if _, err := os.Lstat(activationDir); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return nil, fmt.Errorf("inspect recovered activation marker: %w", err)
		}
		if err := requireRegularDirectory(activationDir); err != nil {
			return nil, err
		}
		restoreIDs = append(restoreIDs, restoreID)
	}
	return restoreIDs, nil
}
