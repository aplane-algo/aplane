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

// TestGenerationCommitsAreValidated keeps the Mint validation opt-out in test
// code. Every production generation commit runs the caller's semantic
// candidate validation before publication.
func TestGenerationCommitsAreValidated(t *testing.T) {
	root := filepath.Join("..", "..")
	allowed := filepath.Join(root, "internal", "genstore", "genstoretest")
	for _, subtree := range []string{"cmd", "internal", "pkg", "lsig"} {
		err := filepath.WalkDir(filepath.Join(root, subtree), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") ||
				strings.HasPrefix(path, allowed+string(filepath.Separator)) {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(data), "SkipCandidateValidation: true") {
				t.Errorf("%s skips generation candidate validation; production commits must supply ValidateCandidate", path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
