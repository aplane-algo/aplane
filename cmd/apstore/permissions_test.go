// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCmdPermissionsMigrateRejectsLocalInstallWithoutMutation(t *testing.T) {
	oldDataDirectory := dataDirectory
	dataDirectory = t.TempDir()
	t.Cleanup(func() { dataDirectory = oldDataDirectory })

	binDir := filepath.Join(dataDirectory, "bin")
	if err := os.Mkdir(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(binDir, "apsigner")
	if err := os.WriteFile(binaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	err := cmdPermissions([]string{"migrate"})
	if err == nil || !strings.Contains(err.Error(), "only supported for systemd-managed") {
		t.Fatalf("cmdPermissions(migrate) error = %v, want local-store rejection", err)
	}
	info, statErr := os.Stat(binaryPath)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("binary mode = %04o after rejected migration, want 0755", got)
	}
}

func TestConfiguredLiveAuditSocketPathUsesSameUIDConfig(t *testing.T) {
	root := t.TempDir()
	socketPath := filepath.Join(root, "custom.sock")
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte("ipc_path: "+socketPath+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := configuredLiveAuditSocketPath(root)
	if err != nil {
		t.Fatal(err)
	}
	if got != socketPath {
		t.Fatalf("configuredLiveAuditSocketPath() = %q, want %q", got, socketPath)
	}
}

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
