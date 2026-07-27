// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package recovered

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// BatchInfo is the non-secret inventory projection of a recovered batch.
type BatchInfo struct {
	RestoreID          string
	CreatedAt          time.Time
	ArchiveName        string
	ArchiveSHA256      string
	SourceNodeRole     string
	SourcePolicyStatus SourcePolicyStatus
	SourcePolicySHA256 string
	EntryCount         int
	// ActivationState is empty for an inactive batch; otherwise the journal
	// state of the batch's incomplete activation ("applying",
	// "rolling_back", "completed"), or "unknown" when a marker exists but
	// its journal cannot be read.
	ActivationState string
}

// List validates and returns published recovered batches newest first.
// Unpublished StagingDirPrefix directories are ignored. Any other unknown or
// invalid root entry fails closed.
func List(paths storepaths.Paths, identityID string, masterKey []byte) ([]BatchInfo, error) {
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

	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("scan recovered batch root: %w", err)
	}
	batches := make([]BatchInfo, 0, len(entries))
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
		batch, err := LoadBatch(paths, identityID, restoreID, masterKey)
		if err != nil {
			return nil, fmt.Errorf("load recovered batch %s: %w", restoreID, err)
		}
		batches = append(batches, BatchInfo{
			RestoreID:          batch.RestoreID,
			CreatedAt:          batch.CreatedAt,
			ArchiveName:        batch.ArchiveName,
			ArchiveSHA256:      batch.ArchiveSHA256,
			SourceNodeRole:     batch.SourceNodeRole,
			SourcePolicyStatus: batch.SourcePolicyStatus,
			SourcePolicySHA256: batch.SourcePolicySHA256,
			EntryCount:         len(batch.Entries),
			ActivationState:    batchActivationState(paths, identityID, restoreID, masterKey),
		})
		crypto.ZeroBytes(batch.SourcePolicyYAML)
	}
	slices.SortFunc(batches, func(a, b BatchInfo) int {
		if order := b.CreatedAt.Compare(a.CreatedAt); order != 0 {
			return order
		}
		return strings.Compare(a.RestoreID, b.RestoreID)
	})
	return batches, nil
}

// batchActivationState reports the durable activation state of one batch:
// empty when no marker exists, the journal state when it can be read, and
// "unknown" for a marker whose journal is unreadable (still incomplete —
// reconciliation decides what to do with it).
func batchActivationState(paths storepaths.Paths, identityID, restoreID string, masterKey []byte) string {
	dir := paths.RecoveredActivationDir(identityID, restoreID)
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		return ""
	}
	var journal ActivationJournal
	if err := readEncryptedJSON(paths.RecoveredActivationJournalPath(identityID, restoreID), masterKey, &journal); err != nil {
		return "unknown"
	}
	if err := validateActivationJournal(&journal); err != nil || journal.RestoreID != restoreID {
		return "unknown"
	}
	return string(journal.State)
}
