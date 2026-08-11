// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/storelock"
)

func TestPermissionsConvertManagedLockFailsBeforeMetadataPublication(t *testing.T) {
	root := t.TempDir()
	shared, err := storelock.AcquireShared(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = shared.Close() }()

	release, err := acquireOfflineMutationLockForArgs(
		[]string{"permissions", "convert-managed", "--uid", "123", "--gid", "456"}, root,
	)
	if release != nil {
		release()
	}
	if err == nil || !strings.Contains(err.Error(), "holds the store lock") {
		t.Fatalf("conversion lock error = %v, want busy-store refusal", err)
	}
	for _, absent := range []string{".prod", filepath.Join("install", "service-principal.json")} {
		if _, statErr := os.Lstat(filepath.Join(root, absent)); !os.IsNotExist(statErr) {
			t.Fatalf("failed conversion lock created %s: %v", absent, statErr)
		}
	}
}

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

func TestCmdPermissionsPreflightWorksBeforeManagedMetadata(t *testing.T) {
	oldDataDirectory := dataDirectory
	dataDirectory = t.TempDir()
	t.Cleanup(func() { dataDirectory = oldDataDirectory })
	if err := os.Chmod(dataDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDirectory, "config.yaml"), []byte("legacy\n"), 0o660); err != nil {
		t.Fatal(err)
	}

	if err := cmdPermissions([]string{"preflight"}); err != nil {
		t.Fatalf("cmdPermissions(preflight) error = %v", err)
	}
	for _, absent := range []string{".prod", ".apstore.lock", filepath.Join("install", "service-principal.json")} {
		if _, err := os.Lstat(filepath.Join(dataDirectory, absent)); !os.IsNotExist(err) {
			t.Fatalf("preflight created %s: %v", absent, err)
		}
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

func TestStorePermissionOwnerUsesManagedServicePrincipal(t *testing.T) {
	oldManagedStoreOwner := managedStoreOwner
	managedStoreOwner = func(root string) (int, int, error) {
		if root != "/managed/store" {
			t.Fatalf("managed owner root = %q", root)
		}
		return 123, 456, nil
	}
	t.Cleanup(func() { managedStoreOwner = oldManagedStoreOwner })

	uid, gid, err := storePermissionOwner("/managed/store", true)
	if err != nil {
		t.Fatal(err)
	}
	if uid != 123 || gid != 456 {
		t.Fatalf("storePermissionOwner(managed) = %d:%d, want 123:456", uid, gid)
	}
}
