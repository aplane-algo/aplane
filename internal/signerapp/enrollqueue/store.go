// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package enrollqueue

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aplane-algo/aplane/internal/fsutil"
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

// Publish writes the queue to path atomically and durably with owner-only
// permissions: a reader sees the old document or the new one, never a
// partial write, and every step's failure is reported. A failure after the
// rename (the directory fsync) leaves the new file in place but possibly not
// durable, so callers treat the on-disk state as unknown and reload.
func Publish(path string, q *Queue) error {
	dir := filepath.Dir(path)
	if err := fsutil.MkdirAllPrivate(dir); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := fsutil.WriteFileDurable(path, q.Marshal()); err != nil {
		return fmt.Errorf("publish enrollment queue: %w", err)
	}
	return nil
}
