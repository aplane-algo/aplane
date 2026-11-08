// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"os"
	"path/filepath"
	"slices"
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
		"aplane." + "falcon1024-cosigner-ed25519" + ".v1",
		"aplane." + "falcon1024-cosigner-falcon1024" + ".v1",
		"aplane." + "cosigner-ed25519" + ".v1",
		"aplane." + "falcon1024-admin-allowlist" + ".v1",
		"aplane." + "falcon1024-hashlock" + ".v1",
		"aplane." + "ed25519-allowlist" + ".v1",
		"aplane." + "cosigner-falcon1024" + ".v1",
		"aplane." + "bounded-admin-key-bundle" + ".v1",
		"aplane." + "bounded-admin-key-private" + ".v1",
		"aplane." + "bounded-admin-key-public" + ".v1",
		"aplane." + "cosigner-public-key" + ".v1",
		// The contract-admin key and its ceremony.
		"ap" + "rekey",
		"internal/" + "boundedadmin",
		"apbounded" + "adminapp",
		"witness/" + "artifact",
		"/sign/" + "bounded-admin",
		"aplane." + "bounded-admin-partial" + ".v1",
		"APLANE_BOUNDED_" + "ADMIN_AUTH_V1",
		"APLANE_BOUNDED_" + "ADMIN_PROGRAM_V1",
		"bounded_" + "admin_public_key",
		"bounded_admin_" + "required",
		"bounded_admin_" + "target_rejected",
		".adm" + ".json",
		"aplane." + "falcon1024-allowlist-lock" + ".v1",
		"aplane." + "corridor" + ".v1",
		"aplane." + "falcon1024-allowlist" + ".v1",
		"aplane." + "falcon1024-allowlist" + ".v2",
		"aplane." + "falcon1024-timelock" + ".v1",
		"library/" + "retired",
		"bounded_admin_" + "operation_requires_review",
		"Bounded1" + "Manifest",
		"lsig/" + "falcon1024_ed25519",
		"lsig/" + "ecdsak1",
		"cosigner_" + "ed25519",
	}
	// The installers name a retired binary only to delete it from an upgraded or
	// uninstalled machine, or to find it still running before they do. Only those
	// lines are exempt, so installing it again would still be caught.
	removesRetired := map[string][]string{
		"../../install.sh":   {"ap" + "rekey"},
		"../../uninstall.sh": {"ap" + "rekey"},
	}
	removalLine := func(line string) bool {
		line = strings.TrimSpace(line)
		return strings.HasPrefix(line, "rm -f ") || strings.HasPrefix(line, "for name in ")
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
		// The release notes are history: they name what each release retired.
		if filepath.ToSlash(path) == "../../docs/RELEASE_NOTES.md" {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		lower := strings.ToLower(string(content))
		for _, token := range retired {
			scanned := lower
			if slices.Contains(removesRetired[filepath.ToSlash(path)], token) {
				var kept []string
				for _, line := range strings.Split(lower, "\n") {
					if !removalLine(line) {
						kept = append(kept, line)
					}
				}
				scanned = strings.Join(kept, "\n")
			}
			if strings.Contains(scanned, strings.ToLower(token)) {
				t.Errorf("%s contains retired key-type product vocabulary %q", path, token)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan repository key-type vocabulary: %v", err)
	}
}
