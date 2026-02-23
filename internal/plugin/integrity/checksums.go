// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package integrity

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ChecksumEntry represents a single entry in the checksums file
type ChecksumEntry struct {
	Hash     string // 64-character lowercase hex SHA256
	Filename string // Relative path from plugin directory
}

// ChecksumFile represents a parsed checksums.sha256 file
type ChecksumFile struct {
	Entries []ChecksumEntry
	Path    string // Absolute path to the checksums file
}

// checksumLineRegex matches "<64-hex-chars>  <filename>" format
// One or two spaces between hash and filename (sha256sum uses two)
var checksumLineRegex = regexp.MustCompile(`^([a-fA-F0-9]{64})\s{1,2}(.+)$`)

// LoadChecksums reads and parses a checksums.sha256 file from a plugin directory
func LoadChecksums(pluginDir string) (*ChecksumFile, error) {
	checksumPath := filepath.Join(pluginDir, "checksums.sha256")

	file, err := os.Open(checksumPath)
	if os.IsNotExist(err) {
		return nil, ErrNoChecksums
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open checksums file: %w", err)
	}
	defer func() { _ = file.Close() }()

	cf := &ChecksumFile{
		Path:    checksumPath,
		Entries: make([]ChecksumEntry, 0),
	}

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		matches := checksumLineRegex.FindStringSubmatch(line)
		if matches == nil {
			return nil, fmt.Errorf("%w: line %d: %q", ErrInvalidChecksumsFormat, lineNum, line)
		}

		cf.Entries = append(cf.Entries, ChecksumEntry{
			Hash:     strings.ToLower(matches[1]),
			Filename: matches[2],
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading checksums file: %w", err)
	}

	if len(cf.Entries) == 0 {
		return nil, fmt.Errorf("%w: no entries found", ErrInvalidChecksumsFormat)
	}

	return cf, nil
}

// FindEntry looks up a filename in the checksums.
// Handles path normalization (e.g., "./plugin" matches "plugin").
func (cf *ChecksumFile) FindEntry(filename string) *ChecksumEntry {
	normalizedTarget := normalizePath(filename)

	for i := range cf.Entries {
		normalizedEntry := normalizePath(cf.Entries[i].Filename)
		if normalizedEntry == normalizedTarget {
			return &cf.Entries[i]
		}
	}
	return nil
}

// normalizePath removes leading "./" and normalizes path separators
func normalizePath(path string) string {
	// Convert to forward slashes for consistent comparison
	normalized := filepath.ToSlash(path)

	// Remove leading "./"
	if len(normalized) > 2 && normalized[:2] == "./" {
		normalized = normalized[2:]
	}

	return normalized
}
