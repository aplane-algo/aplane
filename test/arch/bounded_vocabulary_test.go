// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRetiredBoundedVocabularyDoesNotReturn makes the clean-break rename a
// checked repository contract. temp is deliberately excluded because it holds
// historical implementation plans rather than active product surfaces.
func TestRetiredBoundedVocabularyDoesNotReturn(t *testing.T) {
	root := filepath.Join("..", "..")
	retired := []string{"tx" + "auth", "ap" + "tx" + "auth"}
	textExtensions := map[string]bool{
		".go": true, ".md": true, ".yaml": true, ".yml": true,
		".json": true, ".sh": true, ".service": true, ".toml": true,
	}

	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "temp", "vendor", "node_modules":
				if path != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !textExtensions[filepath.Ext(path)] {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		lower := strings.ToLower(string(content))
		for _, token := range retired {
			if strings.Contains(lower, token) {
				t.Errorf("%s contains retired bounded-protocol vocabulary %q", path, token)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan repository vocabulary: %v", err)
	}
}
