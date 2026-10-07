// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package enrollqueue

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FileName is the queue document's name inside the product store's .ssh
// directory, beside the enrolled-key registry.
const FileName = "pending_enrollments.json"

// Load reads and validates the queue at path. A missing file is an empty
// queue; a file the daemon cannot read completely is an error.
func Load(path string, now time.Time) (*Queue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Queue{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	q, err := Parse(data, now)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return q, nil
}

// Publish writes the queue to path atomically with owner-only permissions:
// a reader sees the old document or the new one, never a partial write.
func Publish(path string, q *Queue) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+FileName+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary enrollment queue: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("set enrollment queue permissions: %w", err)
	}
	if _, err := tmp.Write(q.Marshal()); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write enrollment queue: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("sync enrollment queue: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close enrollment queue: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("publish enrollment queue: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
