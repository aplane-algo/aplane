// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfiguredMigrationSocketPathUsesCustomInStoreConfig(t *testing.T) {
	root := t.TempDir()
	custom := filepath.Join(root, "run", "custom.sock")
	config := []byte("ipc_path: " + custom + "\n")
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), config, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := configuredMigrationSocketPath(root)
	if err != nil {
		t.Fatal(err)
	}
	if got != custom {
		t.Fatalf("configuredMigrationSocketPath() = %q, want %q", got, custom)
	}
}

func TestConfiguredMigrationSocketPathKeepsLegacyDefaultForExternalConfig(t *testing.T) {
	root := t.TempDir()
	external := filepath.Join(filepath.Dir(root), "runtime", "custom.sock")
	config := []byte("ipc_path: " + external + "\n")
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), config, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := configuredMigrationSocketPath(root)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "aplane.sock")
	if got != want {
		t.Fatalf("configuredMigrationSocketPath() = %q, want %q", got, want)
	}
}
