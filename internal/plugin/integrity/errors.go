// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

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

	// ErrManifestNotInChecksums indicates manifest.json is not in the checksums file
	ErrManifestNotInChecksums = errors.New("manifest.json not listed in checksums")

	// ErrChecksumsPathEscape indicates a checksums entry resolves outside the plugin directory.
	ErrChecksumsPathEscape = errors.New("checksums entry escapes plugin directory")

	// ErrNonRegularFile indicates a checksums file or entry is a symlink, directory,
	// FIFO, device, or other non-regular file.
	ErrNonRegularFile = errors.New("plugin file is not a regular file")

	// ErrFileTooLarge indicates a checksums file or entry exceeds the maximum size.
	ErrFileTooLarge = errors.New("plugin file exceeds size limit")
)
