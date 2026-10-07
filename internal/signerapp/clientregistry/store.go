// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientregistry

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/fsutil"
)

// Load reads and validates the registry at path. A missing file is an empty
// registry; any other read failure or a rejected file is an error.
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Parse(nil)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	reg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return reg, nil
}

// Publish writes reg to path as one atomic, durable replacement: a temporary
// file in the same directory, fsync, rename, then fsync of the directory,
// with every step's failure reported. The file is private (0600) and its
// directory is created private (0700) if missing. A failure before the
// rename leaves any existing file untouched; a failure after it (the
// directory fsync) means the new file is in place but may not survive a
// crash, so callers must treat the on-disk state as unknown and reload.
func Publish(path string, reg *Registry) error {
	dir := filepath.Dir(path)
	if err := fsutil.MkdirAllPrivate(dir); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := fsutil.WriteFileDurable(path, reg.Marshal()); err != nil {
		return fmt.Errorf("publish registry: %w", err)
	}
	return nil
}
