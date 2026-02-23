// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package integrity

import "errors"

// Common integrity verification errors
var (
	// ErrNoChecksums indicates the checksums.sha256 file is missing
	ErrNoChecksums = errors.New("checksums.sha256 file not found")

	// ErrInvalidChecksumsFormat indicates the checksums file is malformed
	ErrInvalidChecksumsFormat = errors.New("invalid checksums file format")

	// ErrChecksumMismatch indicates a file's hash doesn't match the expected value
	ErrChecksumMismatch = errors.New("checksum verification failed")

	// ErrMissingFile indicates a file listed in checksums doesn't exist
	ErrMissingFile = errors.New("file listed in checksums not found")

	// ErrExecutableNotInChecksums indicates the executable is not in the checksums file
	ErrExecutableNotInChecksums = errors.New("executable not listed in checksums")
)
