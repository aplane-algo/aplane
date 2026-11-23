// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package integrity provides SHA256 checksum verification for external plugins.
// It implements HashiCorp-style integrity verification where plugins must include
// a checksums.sha256 file that lists SHA256 hashes for plugin files.
package integrity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/fsutil"
)

const (
	// MaxChecksumsFileBytes caps checksums.sha256 reads on the host.
	MaxChecksumsFileBytes int64 = 1 << 20

	// MaxChecksumEntryBytes caps individual plugin file reads hashed on the host
	// (accommodates single-executable runtime bundles while preventing unbounded reads).
	MaxChecksumEntryBytes int64 = 512 << 20
)

var (
	maxChecksumsFileBytes = MaxChecksumsFileBytes
	maxChecksumEntryBytes = MaxChecksumEntryBytes
)

// Verifier handles plugin integrity verification
type Verifier struct{}

// NewVerifier creates a new integrity verifier
func NewVerifier() *Verifier {
	return &Verifier{}
}

// VerifyManifest verifies manifest.json before discovery trusts manifest fields.
func (v *Verifier) VerifyManifest(pluginDir string) error {
	checksums, err := LoadChecksums(pluginDir)
	if err != nil {
		return err
	}
	entry := checksums.FindEntry("manifest.json")
	if entry == nil {
		return fmt.Errorf("%w: manifest.json", ErrManifestNotInChecksums)
	}
	return verifyChecksumEntry(pluginDir, *entry)
}

// VerifyPlugin verifies all checksums for a plugin directory.
// Returns nil if verification succeeds.
// The executablePath should be the executable value from manifest.json
// (e.g., "./my-plugin" or "my-plugin").
func (v *Verifier) VerifyPlugin(pluginDir string, executablePath string) error {
	// Load checksums file
	checksums, err := LoadChecksums(pluginDir)
	if err != nil {
		return err
	}

	if checksums.FindEntry("manifest.json") == nil {
		return fmt.Errorf("%w: manifest.json", ErrManifestNotInChecksums)
	}

	// Verify executable is in checksums (mandatory)
	if checksums.FindEntry(executablePath) == nil {
		return fmt.Errorf("%w: %s", ErrExecutableNotInChecksums, executablePath)
	}

	// Verify all entries in the checksums file
	for _, entry := range checksums.Entries {
		if err := verifyChecksumEntry(pluginDir, entry); err != nil {
			return err
		}
	}

	return nil
}

func verifyChecksumEntry(pluginDir string, entry ChecksumEntry) error {
	filePath, err := resolvePluginPath(pluginDir, entry.Filename)
	if err != nil {
		return err
	}

	actualHash, _, err := fsutil.RegularFileSHA256Limited(filePath, maxChecksumEntryBytes)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("%w: %s", ErrMissingFile, entry.Filename)
		case errors.Is(err, fsutil.ErrNotRegularFile):
			return fmt.Errorf("%w: %s", ErrNonRegularFile, entry.Filename)
		case errors.Is(err, fsutil.ErrFileTooLarge):
			return fmt.Errorf("%w: %s", ErrFileTooLarge, entry.Filename)
		default:
			return fmt.Errorf("failed to hash %s: %w", entry.Filename, err)
		}
	}

	if actualHash != entry.Hash {
		return fmt.Errorf("%w: %s (expected %s..., got %s...)",
			ErrChecksumMismatch, entry.Filename, entry.Hash[:16], actualHash[:16])
	}
	return nil
}

// GenerateChecksums creates checksums.sha256 content for a plugin directory.
// Files should be relative paths from the plugin directory.
func GenerateChecksums(pluginDir string, files []string) (string, error) {
	var result strings.Builder
	result.WriteString("# checksums.sha256\n")
	result.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().UTC().Format(time.RFC3339)))
	result.WriteString("#\n")

	for _, file := range files {
		filePath, err := resolvePluginPath(pluginDir, file)
		if err != nil {
			return "", err
		}
		hash, _, err := fsutil.RegularFileSHA256Limited(filePath, maxChecksumEntryBytes)
		if err != nil {
			switch {
			case errors.Is(err, fsutil.ErrNotRegularFile):
				return "", fmt.Errorf("%w: %s", ErrNonRegularFile, file)
			case errors.Is(err, fsutil.ErrFileTooLarge):
				return "", fmt.Errorf("%w: %s", ErrFileTooLarge, file)
			default:
				return "", fmt.Errorf("failed to hash %s: %w", file, err)
			}
		}
		// Use two spaces between hash and filename (sha256sum format)
		result.WriteString(fmt.Sprintf("%s  %s\n", hash, file))
	}

	return result.String(), nil
}

func resolvePluginPath(pluginDir, entry string) (string, error) {
	root, err := filepath.Abs(pluginDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve plugin directory: %w", err)
	}

	path := filepath.Join(root, entry)
	cleanPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("failed to resolve checksums entry %s: %w", entry, err)
	}

	rel, err := filepath.Rel(root, cleanPath)
	if err != nil {
		return "", fmt.Errorf("failed to validate checksums entry %s: %w", entry, err)
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %s", ErrChecksumsPathEscape, entry)
	}
	if err := checkNoSymlinkAncestors(root, rel, entry); err != nil {
		return "", err
	}

	return cleanPath, nil
}

// checkNoSymlinkAncestors rejects intermediate symlink or non-directory path
// segments inside the plugin directory so host-side verification cannot follow
// a subdirectory symlink outside the plugin root.
func checkNoSymlinkAncestors(root, rel, entry string) error {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	cur := root
	for _, part := range parts[:len(parts)-1] {
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return fmt.Errorf("failed to inspect path %s: %w", entry, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%w: %s", ErrNonRegularFile, entry)
		}
	}
	return nil
}
