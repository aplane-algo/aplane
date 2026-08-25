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

// TestProductRuntimeHasNoSelectorOrOwnershipGraph keeps registry, grant, and
// owner-keyed runtime-selection machinery out of the product runtime.
func TestProductRuntimeHasNoSelectorOrOwnershipGraph(t *testing.T) {
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
				t.Errorf("%s violates the fixed product-runtime boundary with shape %q", path, shape)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestProductCommandsExposeNoIdentitySelector keeps the product CLI fixed to
// the one product store.
func TestProductCommandsExposeNoIdentitySelector(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(filepath.Join(root, "cmd"), func(path string, entry fs.DirEntry, walkErr error) error {
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
		if strings.Contains(text, `"-identity"`) || strings.Contains(text, `"identity"`) {
			t.Errorf("%s adds a product-facing identity selector", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
