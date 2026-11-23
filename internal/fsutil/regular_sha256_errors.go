// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package fsutil

import "errors"

var (
	// ErrNotRegularFile indicates a path is a symlink, directory, FIFO, device,
	// or other non-regular file where a regular file is required.
	ErrNotRegularFile = errors.New("path is not a regular file")

	// ErrFileTooLarge indicates a regular file exceeded the caller's byte limit.
	ErrFileTooLarge = errors.New("file exceeds size limit")
)
