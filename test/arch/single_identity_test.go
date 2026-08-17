// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSingleIdentityBoundaryShapesDoNotRegrow pins the first simplification
// boundary while the remaining session/runtime adapters are removed in later
// slices. Storage identity parameters are intentionally outside this check.
func TestSingleIdentityBoundaryShapesDoNotRegrow(t *testing.T) {
	root := filepath.Join("..", "..")
	forbidden := []string{
		"RegistryAuthenticator",
		"targetAnyIdentity",
		"subjectGroupPrefix",
		"type Grant struct",
		"storeMutationLocks",
		"templateProviderOwners",
	}
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, shape := range forbidden {
			if strings.Contains(string(data), shape) {
				t.Errorf("%s contains removed single-identity boundary shape %q", path, shape)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	err = filepath.WalkDir(filepath.Join(root, "cmd"), func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		text := string(data)
		if filepath.Clean(path) == filepath.Clean(filepath.Join(root, "cmd", "appass", "main.go")) {
			// appass manually parses its small flag set. Keep exact stale-input
			// rejection literals without treating them as a live selector.
			for _, removed := range []string{`"-identity"`, `"--identity"`, `"-identity="`, `"--identity="`} {
				text = strings.ReplaceAll(text, removed, "")
			}
		}
		if strings.Contains(text, `"-identity"`) || strings.Contains(text, `"identity"`) {
			t.Errorf("%s adds a product-facing identity selector", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
