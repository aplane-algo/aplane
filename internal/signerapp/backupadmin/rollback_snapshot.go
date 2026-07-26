// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/aplane-algo/aplane/internal/backup/recovered"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

var activationSnapshotDirectories = []string{"keys", "keytypes"}

func captureActivationSnapshot(
	paths storepaths.Paths,
	identityID, restoreID string,
) (*recovered.RollbackSnapshot, error) {
	snapshot := &recovered.RollbackSnapshot{
		RestoreID:   restoreID,
		Directories: make([]recovered.RollbackDirectory, 0, len(activationSnapshotDirectories)),
	}
	success := false
	defer func() {
		if !success {
			snapshot.Zero()
		}
	}()
	identityDir := paths.IdentityDir(identityID)
	for _, relative := range activationSnapshotDirectories {
		dir, err := captureActivationDirectory(filepath.Join(identityDir, relative), relative)
		if err != nil {
			return nil, err
		}
		snapshot.Directories = append(snapshot.Directories, dir)
	}
	success = true
	return snapshot, nil
}

func captureActivationDirectory(path, relative string) (recovered.RollbackDirectory, error) {
	snapshot := recovered.RollbackDirectory{RelativePath: relative}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return snapshot, nil
	}
	if err != nil {
		return snapshot, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return snapshot, fmt.Errorf("activation namespace is not a regular directory: %s", path)
	}
	snapshot.Existed = true
	entries, err := os.ReadDir(path)
	if err != nil {
		return snapshot, err
	}
	for _, entry := range entries {
		data, mode, err := fsutil.ReadRegularFile(filepath.Join(path, entry.Name()))
		if err != nil {
			for i := range snapshot.Files {
				crypto.ZeroBytes(snapshot.Files[i].Data)
			}
			return recovered.RollbackDirectory{}, fmt.Errorf("snapshot active file %s: %w", entry.Name(), err)
		}
		sum := sha256.Sum256(data)
		snapshot.Files = append(snapshot.Files, recovered.RollbackFile{
			Name:   entry.Name(),
			Mode:   uint32(mode),
			SHA256: hex.EncodeToString(sum[:]),
			Data:   data,
		})
	}
	slices.SortFunc(snapshot.Files, func(a, b recovered.RollbackFile) int {
		return strings.Compare(a.Name, b.Name)
	})
	return snapshot, nil
}

func restoreActivationSnapshot(
	paths storepaths.Paths,
	identityID string,
	snapshot *recovered.RollbackSnapshot,
) error {
	if snapshot == nil {
		return fmt.Errorf("activation rollback snapshot is nil")
	}
	if len(snapshot.Directories) != len(activationSnapshotDirectories) {
		return fmt.Errorf("activation rollback snapshot namespace count mismatch")
	}
	identityDir := paths.IdentityDir(identityID)
	for i, expected := range activationSnapshotDirectories {
		dir := snapshot.Directories[i]
		if dir.RelativePath != expected {
			return fmt.Errorf("unexpected activation rollback namespace %q", dir.RelativePath)
		}
		if err := restoreActivationDirectory(filepath.Join(identityDir, expected), dir); err != nil {
			return err
		}
	}
	return nil
}

func restoreActivationDirectory(path string, snapshot recovered.RollbackDirectory) error {
	info, err := os.Lstat(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	dirExisted := err == nil
	if dirExisted {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("activation namespace is not a regular directory: %s", path)
		}
		snapshotFiles := make(map[string]struct{}, len(snapshot.Files))
		for _, file := range snapshot.Files {
			snapshotFiles[file.Name] = struct{}{}
		}
		var ownedFiles map[string]struct{}
		if snapshot.Owned != nil {
			ownedFiles = make(map[string]struct{}, len(snapshot.Owned))
			for _, name := range snapshot.Owned {
				ownedFiles[name] = struct{}{}
			}
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if ownedFiles != nil {
				_, inSnapshot := snapshotFiles[entry.Name()]
				_, isOwned := ownedFiles[entry.Name()]
				if !inSnapshot && !isOwned {
					// The activation could not have written this file; it
					// belongs to another operation and must survive rollback.
					// (Legacy snapshots without ownership keep the historical
					// clear-directory behavior.)
					continue
				}
			}
			target := filepath.Join(path, entry.Name())
			if _, _, err := fsutil.ReadRegularFile(target); err != nil {
				return fmt.Errorf("refuse to replace unsupported rollback target %s: %w", target, err)
			}
			if err := os.Remove(target); err != nil {
				return err
			}
		}
	}
	if !snapshot.Existed {
		if !dirExisted {
			return nil
		}
		if snapshot.Owned != nil {
			remaining, err := os.ReadDir(path)
			if err != nil {
				return err
			}
			if len(remaining) > 0 {
				// Ownership-limited rollback left files that belong to other
				// operations; the directory must survive with them.
				return fsutil.SyncDir(path)
			}
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		return fsutil.SyncDir(filepath.Dir(path))
	}
	if err := fsutil.MkdirAll(path); err != nil {
		return err
	}
	for _, file := range snapshot.Files {
		target := filepath.Join(path, file.Name)
		// Durable restore: the journal and marker may only be removed once
		// every restored byte is on disk. [P1c]
		if err := fsutil.WriteFileDurable(target, file.Data); err != nil {
			return err
		}
		if err := os.Chmod(target, os.FileMode(file.Mode)); err != nil {
			return err
		}
	}
	return fsutil.SyncDir(path)
}
