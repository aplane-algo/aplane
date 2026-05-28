// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DiscoverIdentities scans the identities/ directory under the given data root
// and returns the identity IDs found (each subdirectory name is an identity).
// Returns an empty slice if identities/ does not exist.
func DiscoverIdentities(dataRoot string) ([]string, error) {
	usersDir := filepath.Join(dataRoot, "identities")
	entries, err := os.ReadDir(usersDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read identities directory: %w", err)
	}

	var ids []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Skip hidden directories and names with path-traversal characters
		if strings.HasPrefix(name, ".") || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
			continue
		}
		ids = append(ids, name)
	}
	return ids, nil
}
