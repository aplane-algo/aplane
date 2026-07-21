// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ScanBackupFiles scans a directory for .apb backup files and returns their addresses.
func ScanBackupFiles(dir string) ([]string, error) {
	return scanByExtension(dir, ".apb")
}

func scanByExtension(dir, ext string) ([]string, error) {
	pattern := filepath.Join(dir, "*"+ext)
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to scan directory: %w", err)
	}

	addresses := make([]string, 0, len(matches))
	for _, match := range matches {
		filename := filepath.Base(match)
		address := strings.TrimSuffix(filename, ext)
		addresses = append(addresses, address)
	}

	return addresses, nil
}

// FormatFileSize formats a file size in human-readable format
func FormatFileSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
	)

	if bytes < KB {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < MB {
		return fmt.Sprintf("%.1f KB", float64(bytes)/KB)
	}
	return fmt.Sprintf("%.1f MB", float64(bytes)/MB)
}
