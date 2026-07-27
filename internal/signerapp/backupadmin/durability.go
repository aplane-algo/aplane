// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/backup/recovered"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// syncActiveNamespaces fsyncs every regular file in the identity's active
// keys and key-type namespaces, then the directories themselves. Runs after
// all activation or rollback entry changes: no recovery evidence may be
// removed while an active write could still be sitting in the page cache.
// [P1c]
func syncActiveNamespaces(paths storepaths.Paths, identityID string) error {
	identityDir := paths.IdentityDir(identityID)
	for _, relative := range activationSnapshotDirectories {
		dir := filepath.Join(identityDir, relative)
		info, err := os.Lstat(dir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("activation namespace is not a regular directory: %s", dir)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !entry.Type().IsRegular() {
				continue
			}
			if err := syncFile(filepath.Join(dir, entry.Name())); err != nil {
				return err
			}
		}
		if err := fsutil.SyncDir(dir); err != nil {
			return err
		}
	}
	return nil
}

func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}

// snapshotOwnership derives every active filename the reviewed batch may
// create or replace, keyed by snapshot namespace. Recorded in the rollback
// snapshot so rollback removes only entries this activation owns and can
// never delete a file written by an unrelated operation. [P1]
func snapshotOwnership(entries []adminproto.RecoveredReviewEntry) (map[string][]string, error) {
	owned := make(map[string]map[string]struct{}, len(activationSnapshotDirectories))
	add := func(namespace, name string) {
		if owned[namespace] == nil {
			owned[namespace] = make(map[string]struct{})
		}
		owned[namespace][name] = struct{}{}
	}
	for _, entry := range entries {
		name, err := keys.CanonicalManagedCredentialFilename(entry.Selector, entry.Category)
		if err != nil {
			return nil, fmt.Errorf("derive active filename for %s: %w", entry.Selector, err)
		}
		add("keys", name)
		// Sentry credentials publish a public witness sidecar beside the key;
		// claim it even for non-sentry entries (a name that is never written
		// is harmless, a written name that is not owned would survive
		// rollback).
		add("keys", entry.Selector+keys.WitnessPublicMetadataSuffix)
		if entry.KeyType != "" {
			add("keytypes", entry.KeyType+".json")
			// Archive-supplied templates install beside the record
			// (restore.go template plans). An unowned template written by
			// a failed activation would survive rollback and later be
			// treated as existing keystore material in fingerprint-conflict
			// decisions; claiming a name that is never written is harmless.
			add("keytypes", entry.KeyType+".template")
		}
	}
	result := make(map[string][]string, len(owned))
	for namespace, names := range owned {
		sorted := make([]string, 0, len(names))
		for name := range names {
			sorted = append(sorted, name)
		}
		slices.Sort(sorted)
		result[namespace] = sorted
	}
	return result, nil
}

// attachSnapshotOwnership marks every snapshot namespace with the file names
// the activation owns. A non-nil (possibly empty) Owned slice switches
// rollback from clear-directory to owned-entries-only deletion.
func attachSnapshotOwnership(snapshot *recovered.RollbackSnapshot, owned map[string][]string) {
	for i := range snapshot.Directories {
		names := owned[snapshot.Directories[i].RelativePath]
		if names == nil {
			names = []string{}
		}
		snapshot.Directories[i].Owned = names
	}
}
