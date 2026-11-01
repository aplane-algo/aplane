// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/fsutil"
)

// Conflict is how a file on disk differs from what was loaded.
type Conflict int

const (
	ConflictNone Conflict = iota
	// ConflictModified: the file's bytes changed since they were loaded.
	ConflictModified
	// ConflictDeleted: the file existed when loaded and is gone.
	ConflictDeleted
	// ConflictCreated: no file existed when loaded, and one does now.
	ConflictCreated
)

func (c Conflict) String() string {
	return [...]string{"none", "changed on disk", "deleted from disk", "created on disk"}[c]
}

// ConflictError is returned by Write when the file on disk is not what was
// loaded. Disk holds the current bytes, nil when the file is gone.
type ConflictError struct {
	Path string
	Kind Conflict
	Disk []byte
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("%s was %s since it was loaded", e.Path, e.Kind)
}

// DiskState reads the file as it is now and compares it with what was
// loaded. disk is its current bytes, nil when it does not exist.
func (f *File) DiskState() (conflict Conflict, disk []byte, err error) {
	data, _, err := fsutil.ReadRegularFileLimited(f.Path, maxFileBytes)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if f.Exists {
			return ConflictDeleted, nil, nil
		}
		return ConflictNone, nil, nil
	case err != nil:
		return ConflictNone, nil, fmt.Errorf("cannot read %s: %w", f.Path, err)
	case !f.Exists:
		return ConflictCreated, data, nil
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != f.LoadedSHA256 {
		return ConflictModified, data, nil
	}
	return ConflictNone, data, nil
}

// Write replaces the file with data. Unless overwrite is set, it first checks
// the disk again and returns a *ConflictError if the file is not what was
// loaded; overwrite is for a caller that has shown the user the disk version
// against data and been told to discard it. The write is atomic (temporary
// file, fsync, rename) with mode 0600. Only after it succeeds does the file's
// baseline become data, re-analyzed.
//
// The check and the rename are separate steps, so this is best-effort
// detection, not a compare-and-swap: another writer can still change the file
// between them, and other editors do not honor advisory locks.
func (f *File) Write(data []byte, overwrite bool) error {
	if !overwrite {
		conflict, disk, err := f.DiskState()
		if err != nil {
			return err
		}
		if conflict != ConflictNone {
			return &ConflictError{Path: f.Path, Kind: conflict, Disk: disk}
		}
	}
	if len(data) > maxFileBytes {
		return fmt.Errorf("%s: %d bytes is over the %d-byte limit", f.Path, len(data), maxFileBytes)
	}
	if err := fsutil.WriteFileDurable(f.Path, data); err != nil {
		return fmt.Errorf("write %s: %w", f.Path, err)
	}
	f.setLoaded(data)
	f.analyze(bytes.Clone(data))
	return nil
}
