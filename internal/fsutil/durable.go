// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DurableFileProfile is a closed set of ownership and permission policies for
// durable publication. Callers choose an artifact purpose instead of passing
// arbitrary mode and ownership combinations.
type DurableFileProfile uint8

const (
	// LegacyStoreFileProfile retains the transitional group-readable and
	// group-writable store ceiling. It must not be used for new store designs.
	LegacyStoreFileProfile DurableFileProfile = iota
	// PrivateStoreFileProfile creates service-user-only store files.
	PrivateStoreFileProfile
	// RootCredentialFileProfile creates the narrow root-owned systemd
	// credential exception used by appass.
	RootCredentialFileProfile
)

type durableFilePolicy struct {
	mode        os.FileMode
	preserveGID bool
	owner       *durableOwner
}

type durableOwner struct {
	uid int
	gid int
}

func policyForDurableFileProfile(profile DurableFileProfile) (durableFilePolicy, error) {
	switch profile {
	case LegacyStoreFileProfile:
		return durableFilePolicy{mode: StoreFilePerm, preserveGID: true}, nil
	case PrivateStoreFileProfile:
		return durableFilePolicy{mode: 0o600}, nil
	case RootCredentialFileProfile:
		return durableFilePolicy{mode: 0o600, owner: &durableOwner{uid: 0, gid: 0}}, nil
	default:
		return durableFilePolicy{}, fmt.Errorf("unknown durable file profile %d", profile)
	}
}

// HookOp identifies a durability-relevant operation intercepted by TestHook.
type HookOp string

const (
	// OpFileSync precedes fsync of a written temp file.
	OpFileSync HookOp = "file-sync"
	// OpDirSync precedes fsync of a directory.
	OpDirSync HookOp = "dir-sync"
	// OpRename precedes the rename that publishes a durable write.
	OpRename HookOp = "rename"
)

// TestHook, when non-nil, runs before each durability-relevant operation in
// this package's durable helpers; returning an error aborts that operation
// with the error. Tests use it to assert operation ordering and to inject
// failures at exact crash points. It must be nil in production and is not
// synchronized: set it before concurrent use and clear it after.
var TestHook func(op HookOp, path string) error

func runHook(op HookOp, path string) error {
	if TestHook != nil {
		return TestHook(op, path)
	}
	return nil
}

// WriteFileDurable writes data to path atomically and durably: temp file in
// the destination directory, fsync of the file, rename over the destination,
// fsync of the parent directory. On return the new content survives a crash
// or power loss.
//
// Unlike WriteFile it never falls back to an unsynced in-place write. When
// the destination exists, its mode and group ownership are preserved through
// the replacement; a destination owned by another uid becomes owned by the
// writing process (group access is what the store's permission model
// guarantees, and a silent unsynced fallback is not acceptable on paths that
// require durability).
func WriteFileDurable(path string, data []byte) error {
	return WriteFileDurableWithProfile(path, data, LegacyStoreFileProfile)
}

// WriteFileDurableWithProfile atomically and durably publishes data according
// to a validated artifact profile. Existing permissions are retained only
// when they are more restrictive than the profile ceiling. Symlinks and
// non-regular destinations are rejected before any publication occurs.
func WriteFileDurableWithProfile(path string, data []byte, profile DurableFileProfile) error {
	policy, err := policyForDurableFileProfile(profile)
	if err != nil {
		return err
	}
	return writeFileDurableWithPolicy(path, data, policy)
}

// WriteServiceOwnedFileDurable publishes a private file owned by a resolved
// service account. The mode is fixed at 0600; callers cannot widen it.
func WriteServiceOwnedFileDurable(path string, data []byte, uid, gid int) error {
	if uid < 0 || gid < 0 {
		return fmt.Errorf("invalid service ownership %d:%d", uid, gid)
	}
	return writeFileDurableWithPolicy(path, data, durableFilePolicy{
		mode:  0o600,
		owner: &durableOwner{uid: uid, gid: gid},
	})
}

func writeFileDurableWithPolicy(path string, data []byte, policy durableFilePolicy) error {

	info, statErr := os.Lstat(path)
	if statErr != nil && !os.IsNotExist(statErr) {
		return statErr
	}
	if statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to replace symlink: %s", path)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to replace non-regular file: %s", path)
		}
	}

	dir := filepath.Dir(path)
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect durable-write parent %s: %w", dir, err)
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() {
		return fmt.Errorf("durable-write parent is not a real directory: %s", dir)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		return err
	}

	targetMode := policy.mode
	targetGID := 0
	preserveGID := false
	if statErr == nil {
		// Never carry permissions wider than the selected profile. More
		// restrictive existing permissions remain restrictive.
		targetMode = info.Mode().Perm() & policy.mode
		if policy.preserveGID {
			_, gid, ok := FileOwnership(info)
			targetGID = gid
			preserveGID = ok && targetGID != os.Getgid()
		}
	}

	// Ownership is set on the unpublished descriptor. Chown precedes chmod
	// because chown may clear permission bits on some platforms.
	if policy.owner != nil {
		if err := tmp.Chown(policy.owner.uid, policy.owner.gid); err != nil {
			return fmt.Errorf("set durable temp ownership to %d:%d: %w", policy.owner.uid, policy.owner.gid, err)
		}
	} else if preserveGID {
		if err := tmp.Chown(-1, targetGID); err != nil {
			return err
		}
	}
	if err := tmp.Chmod(targetMode); err != nil {
		return err
	}

	if err := runHook(OpFileSync, path); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := runHook(OpRename, path); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return SyncDir(dir)
}

// SyncDir fsyncs the directory at path, making previously renamed, created,
// or removed entries durable. Platforms without directory fsync (Windows)
// treat it as a no-op.
func SyncDir(path string) error {
	if err := runHook(OpDirSync, path); err != nil {
		return err
	}
	return syncDir(path)
}

// RemoveDurable removes path and fsyncs its parent directory so the removal
// survives a crash. A path that does not exist is not an error: the removal
// it records is already the state on disk.
func RemoveDurable(path string) error {
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return SyncDir(filepath.Dir(path))
}

// RemoveDurableWriteTemps reconciles crash residue created by
// WriteFileDurable for path. The basename+".tmp-" namespace is reserved for
// that helper. Unexpected non-regular artifacts fail closed.
func RemoveDurableWriteTemps(path string) error {
	dir := filepath.Dir(path)
	prefix := filepath.Base(path) + ".tmp-"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var temps []string
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect durable-write temp %s: %w", entry.Name(), err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf(
				"durable-write temp is not a regular file: %s",
				filepath.Join(dir, entry.Name()),
			)
		}
		temps = append(temps, filepath.Join(dir, entry.Name()))
	}
	for _, temp := range temps {
		if err := os.Remove(temp); err != nil {
			return fmt.Errorf("remove durable-write temp %s: %w", filepath.Base(temp), err)
		}
	}
	if len(temps) > 0 {
		return SyncDir(dir)
	}
	return nil
}
