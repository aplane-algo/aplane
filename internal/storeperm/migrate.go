// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeperm

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/fsutil"
)

// MigrationResult summarizes a completed legacy-to-private store migration.
type MigrationResult struct {
	Inspected int
	Changed   int
}

type migrationEntry struct {
	path string
	info os.FileInfo
}

// MigratePrivate validates the complete legacy tree before changing it,
// removes group access at the root first, and then repairs every recognized
// object through an opened descriptor. Structural findings are fatal; owner
// and mode findings are precisely what this operation repairs.
func MigratePrivate(opts Options) (MigrationResult, error) {
	opts.Profile = LegacySharedProfile
	findings, err := Audit(opts)
	if err != nil {
		return MigrationResult{}, err
	}
	for _, finding := range findings {
		switch finding.Code {
		case "owner", "mode", "special-mode":
			// Repairable below.
		default:
			return MigrationResult{}, fmt.Errorf("refusing unsafe signer-store migration: %w", finding)
		}
	}

	root, err := filepath.Abs(filepath.Clean(opts.Root))
	if err != nil {
		return MigrationResult{}, fmt.Errorf("resolve store root: %w", err)
	}
	legacySocket, err := recognizedLegacySocket(root, opts.SocketPath)
	if err != nil {
		return MigrationResult{}, err
	}
	entries, err := migrationInventory(root, legacySocket)
	if err != nil {
		return MigrationResult{}, err
	}
	// WalkDir normally returns the root first. Make that security property
	// explicit: once the root is 0700, a former group member cannot race the
	// descendant repairs.
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].path == root {
			return true
		}
		if entries[j].path == root {
			return false
		}
		return entries[i].path < entries[j].path
	})

	result := MigrationResult{Inspected: len(entries)}
	privatePolicy, err := policyForProfile(PrivateServiceProfile)
	if err != nil {
		return result, err
	}
	for _, entry := range entries {
		if entry.info.Mode()&os.ModeSocket != 0 {
			if err := removeInventoriedLegacySocket(entry, legacySocket); err != nil {
				return result, err
			}
			result.Changed++
			continue
		}
		expect := expectedArtifact(root, entry.path, entry.info, opts, privatePolicy)
		uid, gid, ok := fsutil.FileOwnership(entry.info)
		if !ok {
			return result, fmt.Errorf("ownership metadata unavailable for %s", entry.path)
		}
		changed := uid != expect.uid || gid != expect.gid || entry.info.Mode().Perm() != expect.mode ||
			entry.info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0
		if err := repairOpenedEntry(entry, expect.uid, expect.gid, expect.mode); err != nil {
			return result, err
		}
		if changed {
			result.Changed++
		}
	}
	if err := syncMigratedDirectories(entries); err != nil {
		return result, err
	}

	privateOpts := opts
	privateOpts.Profile = PrivateServiceProfile
	privateOpts.SocketPath = ""
	post, err := Audit(privateOpts)
	if err != nil {
		return result, err
	}
	if len(post) != 0 {
		return result, fmt.Errorf("private signer-store verification failed after migration: %w", post[0])
	}
	return result, nil
}

func recognizedLegacySocket(root, socketPath string) (string, error) {
	if socketPath == "" {
		return "", nil
	}
	socket, err := filepath.Abs(filepath.Clean(socketPath))
	if err != nil {
		return "", fmt.Errorf("resolve legacy signer socket: %w", err)
	}
	rel, err := filepath.Rel(root, socket)
	if err != nil || rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("legacy signer socket is outside store root: %s", socket)
	}
	return socket, nil
}

func removeInventoriedLegacySocket(entry migrationEntry, socketPath string) error {
	if socketPath == "" || !sameCleanPath(entry.path, socketPath) {
		return fmt.Errorf("refusing unexpected socket during signer-store migration: %s", entry.path)
	}
	info, err := os.Lstat(entry.path)
	if err != nil {
		return fmt.Errorf("inspect legacy signer socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 || !os.SameFile(entry.info, info) {
		return fmt.Errorf("legacy signer socket changed during migration: %s", entry.path)
	}
	if err := os.Remove(entry.path); err != nil {
		return fmt.Errorf("remove stale legacy signer socket: %w", err)
	}
	return nil
}

func migrationInventory(root, legacySocket string) ([]migrationEntry, error) {
	var entries []migrationEntry
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink during signer-store migration: %s", path)
		}
		recognizedSocket := info.Mode()&os.ModeSocket != 0 && sameCleanPath(path, legacySocket)
		if !info.IsDir() && !info.Mode().IsRegular() && !recognizedSocket {
			return fmt.Errorf("refusing unexpected object during signer-store migration: %s", path)
		}
		if info.Mode().IsRegular() {
			if links, ok := regularFileLinkCount(info); ok && links != 1 {
				return fmt.Errorf("refusing hardlinked file during signer-store migration: %s", path)
			}
		}
		entries = append(entries, migrationEntry{path: path, info: info})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("inventory signer store for migration: %w", err)
	}
	return entries, nil
}

func repairOpenedEntry(entry migrationEntry, uid, gid int, mode os.FileMode) error {
	file, err := os.Open(entry.path)
	if err != nil {
		return fmt.Errorf("open signer-store entry %s: %w", entry.path, err)
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect opened signer-store entry %s: %w", entry.path, err)
	}
	if !os.SameFile(entry.info, opened) {
		return fmt.Errorf("signer-store entry changed during migration: %s", entry.path)
	}
	// Chown may clear mode bits, so it must precede chmod.
	if err := file.Chown(uid, gid); err != nil {
		return fmt.Errorf("set signer-store ownership on %s: %w", entry.path, err)
	}
	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("set signer-store mode on %s: %w", entry.path, err)
	}
	return nil
}

func syncMigratedDirectories(entries []migrationEntry) error {
	var dirs []string
	for _, entry := range entries {
		if entry.info.IsDir() {
			dirs = append(dirs, entry.path)
		}
	}
	sort.Slice(dirs, func(i, j int) bool {
		return len(dirs[i]) > len(dirs[j])
	})
	for _, dir := range dirs {
		if err := fsutil.SyncDir(dir); err != nil {
			return fmt.Errorf("sync migrated signer-store directory %s: %w", dir, err)
		}
	}
	return nil
}
