// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRetiredKeyTypeProductsDoNotReturn(t *testing.T) {
	root := filepath.Join("..", "..")
	retired := []string{
		"aplane." + "falcon1024_ed25519" + ".v1",
		"aplane." + "ecdsak1" + ".v1",
		"aplane." + "allowlist" + ".v1",
		"aplane." + "timed-allowlist" + ".v1",
		"aplane." + "falcon1024-sentry-ed25519" + ".v1",
		"aplane." + "falcon1024-sentry-falcon1024" + ".v1",
		"aplane." + "sentry-ed25519" + ".v1",
		"aplane." + "falcon1024-admin-allowlist" + ".v1",
		"aplane." + "falcon1024-hashlock" + ".v1",
		"aplane." + "ed25519-allowlist" + ".v1",
		"lsig/" + "falcon1024_ed25519",
		"lsig/" + "ecdsak1",
		"sentry_" + "ed25519",
	}
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
			case ".git", ".claude", ".codex", "temp", "vendor", "node_modules":
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
			if strings.Contains(lower, strings.ToLower(token)) {
				t.Errorf("%s contains retired key-type product vocabulary %q", path, token)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan repository key-type vocabulary: %v", err)
	}
}
