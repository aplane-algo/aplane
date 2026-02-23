// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

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

	"github.com/aplane-algo/aplane/internal/util"
)

// Verifier handles plugin integrity verification
type Verifier struct{}

// NewVerifier creates a new integrity verifier
func NewVerifier() *Verifier {
	return &Verifier{}
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

	// Verify executable is in checksums (mandatory)
	if checksums.FindEntry(executablePath) == nil {
		return fmt.Errorf("%w: %s", ErrExecutableNotInChecksums, executablePath)
	}

	// Verify all entries in the checksums file
	for _, entry := range checksums.Entries {
		filePath := filepath.Join(pluginDir, entry.Filename)

		actualHash, err := util.ComputeSHA256(filePath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("%w: %s", ErrMissingFile, entry.Filename)
			}
			return fmt.Errorf("failed to hash %s: %w", entry.Filename, err)
		}

		if actualHash != entry.Hash {
			return fmt.Errorf("%w: %s (expected %s..., got %s...)",
				ErrChecksumMismatch, entry.Filename, entry.Hash[:16], actualHash[:16])
		}
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
		filePath := filepath.Join(pluginDir, file)
		hash, err := util.ComputeSHA256(filePath)
		if err != nil {
			return "", fmt.Errorf("failed to hash %s: %w", file, err)
		}
		// Use two spaces between hash and filename (sha256sum format)
		result.WriteString(fmt.Sprintf("%s  %s\n", hash, file))
	}

	return result.String(), nil
}
