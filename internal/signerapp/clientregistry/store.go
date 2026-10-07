// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientregistry

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// Publish writes reg to path as one atomic replacement: a temporary file in
// the same directory, fsync, rename, then fsync of the directory. The file is
// private (0600) and its directory is created private (0700) if missing. A
// failure leaves any existing file untouched.
func Publish(path string, reg *Registry) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".authorized_keys.*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary registry: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("set registry permissions: %w", err)
	}
	if _, err := tmp.Write(reg.Marshal()); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write registry: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("sync registry: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close registry: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("publish registry: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
