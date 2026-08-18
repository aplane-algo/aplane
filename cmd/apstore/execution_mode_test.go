// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/storelock"
)

func TestNormalizeManagedStoreOwnershipUsesConfiguredLegacySocket(t *testing.T) {
	dataDir := t.TempDir()
	customSocket := filepath.Join(dataDir, "custom.sock")
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte("ipc_path: "+customSocket+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldManagedStoreOwner := managedStoreOwner
	managedStoreOwner = func(string) (int, int, error) { return 123, 456, nil }
	t.Cleanup(func() { managedStoreOwner = oldManagedStoreOwner })
	oldMigrateManagedStore := migrateManagedStore
	var gotRoot, gotSocket string
	var gotUID, gotGID int
	migrateManagedStore = func(root string, uid, gid int, socketPath string) error {
		gotRoot, gotUID, gotGID, gotSocket = root, uid, gid, socketPath
		return nil
	}
	t.Cleanup(func() { migrateManagedStore = oldMigrateManagedStore })

	if err := normalizeManagedStoreOwnership(dataDir); err != nil {
		t.Fatalf("normalizeManagedStoreOwnership() error = %v", err)
	}
	if gotRoot != dataDir || gotUID != 123 || gotGID != 456 || gotSocket != customSocket {
		t.Fatalf("migration inputs = %q %d:%d %q, want %q 123:456 %q", gotRoot, gotUID, gotGID, gotSocket, dataDir, customSocket)
	}
}

func TestAcquireOfflineMutationLockAllowsExclusiveMutation(t *testing.T) {
	for _, command := range []string{"governance", "initialize", "rebuild"} {
		release, err := acquireOfflineMutationLock(command, t.TempDir())
		if err != nil {
			t.Fatalf("acquireOfflineMutationLock(%q) error = %v", command, err)
		}
		release()
	}
}

func TestAcquireOfflineMutationLockAllowsReadOnlyCommandWhenSignerLive(t *testing.T) {
	release, err := acquireOfflineMutationLock("verify", t.TempDir())
	if err != nil {
		t.Fatalf("expected read-only command to be allowed, got %v", err)
	}
	release()
}

func TestAcquireOfflineMutationLockRejectsSharedStoreLock(t *testing.T) {
	dataDir := t.TempDir()
	guard, err := storelock.AcquireShared(dataDir)
	if err != nil {
		t.Fatalf("AcquireShared() error = %v", err)
	}
	defer func() { _ = guard.Close() }()

	release, err := acquireOfflineMutationLock("initialize", dataDir)
	if err == nil {
		release()
		t.Fatal("expected store lock acquisition error")
	}
	if !errors.Is(err, storelock.ErrBusy) && !strings.Contains(err.Error(), "holds the store lock") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAcquireOfflineMutationLockForArgsSkipsManagedBackupLock(t *testing.T) {
	dataDir := t.TempDir()

	guard, err := storelock.AcquireExclusive(dataDir)
	if err != nil {
		t.Fatalf("AcquireExclusive() error = %v", err)
	}
	defer func() { _ = guard.Close() }()

	release, err := acquireOfflineMutationLockForArgs([]string{"backup", "create", "all"}, dataDir)
	if err != nil {
		t.Fatalf("acquireOfflineMutationLockForArgs(managed backup) error = %v", err)
	}
	release()
}

func TestPermissionsPreflightBypassesModeGuardAndStoreLock(t *testing.T) {
	dataDir := t.TempDir()
	oldCurrentEUID := currentEUID
	currentEUID = func() int { return 0 }
	t.Cleanup(func() { currentEUID = oldCurrentEUID })

	args := []string{"permissions", "preflight"}
	if err := enforceApstoreExecutionMode(dataDir, args); err != nil {
		t.Fatalf("enforceApstoreExecutionMode(preflight) error = %v", err)
	}
	release, err := acquireOfflineMutationLockForArgs(args, dataDir)
	if err != nil {
		t.Fatalf("acquireOfflineMutationLockForArgs(preflight) error = %v", err)
	}
	release()
	if _, err := os.Lstat(filepath.Join(dataDir, ".apstore.lock")); !os.IsNotExist(err) {
		t.Fatalf("preflight lock path exists: %v", err)
	}
}

func TestManagedRestoreCommandSetMatchesProtocolV4(t *testing.T) {
	for _, command := range []string{"preview", "apply", "rollback", "reconcile"} {
		if !isManagedRestoreCommand([]string{"restore", command}) {
			t.Fatalf("restore %s was not recognized as a managed command", command)
		}
	}
	for _, removed := range []string{"list", "review", "activate", "purge"} {
		if isManagedRestoreCommand([]string{"restore", removed}) {
			t.Fatalf("removed restore command %s remains reachable", removed)
		}
	}
}

func TestEnforceApstoreExecutionModeRejectsRootForLocalDataDir(t *testing.T) {
	oldCurrentEUID := currentEUID
	defer func() {
		currentEUID = oldCurrentEUID
	}()

	dataDir := t.TempDir()
	currentEUID = func() int { return 0 }

	err := enforceApstoreExecutionMode(dataDir, []string{"initialize"})
	if err == nil {
		t.Fatal("enforceApstoreExecutionMode() error = nil, want local root refusal")
	}
	for _, want := range []string{
		"local signer data directory",
		"must not be managed as root",
		"apstore -d " + dataDir + " initialize",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want substring %q", err.Error(), want)
		}
	}
}

func TestEnforceApstoreExecutionModeRejectsNonRootForProductionDataDir(t *testing.T) {
	oldCurrentEUID := currentEUID
	defer func() {
		currentEUID = oldCurrentEUID
	}()

	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, ".prod"), []byte("systemd-managed\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(.prod) error = %v", err)
	}
	currentEUID = func() int { return 1000 }

	err := enforceApstoreExecutionMode(dataDir, []string{"initialize"})
	if err == nil {
		t.Fatal("enforceApstoreExecutionMode() error = nil, want production non-root refusal")
	}
	for _, want := range []string{
		"systemd-managed data directory",
		"requires root",
		"sudo apstore -d " + dataDir + " initialize",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want substring %q", err.Error(), want)
		}
	}
}

func TestEnforceApstoreExecutionModeRejectsForeignOwnedLocalDataDir(t *testing.T) {
	oldCurrentEUID := currentEUID
	defer func() {
		currentEUID = oldCurrentEUID
	}()

	dataDir := t.TempDir()
	info, err := os.Stat(dataDir)
	if err != nil {
		t.Fatalf("Stat(dataDir) error = %v", err)
	}
	uid, _, err := fileOwnerGroup(info)
	if err != nil {
		t.Fatalf("fileOwnerGroup(dataDir) error = %v", err)
	}
	currentEUID = func() int { return uid + 1 }

	err = enforceApstoreExecutionMode(dataDir, []string{"initialize"})
	if err == nil {
		t.Fatal("enforceApstoreExecutionMode() error = nil, want foreign-owner refusal")
	}
	for _, want := range []string{
		"local signer data directory",
		"owned by uid",
		"restore the systemd-managed .prod marker",
		"sudo apstore -d " + dataDir + " initialize",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want substring %q", err.Error(), want)
		}
	}
}

func TestEnforceApstoreExecutionModeAllowsDaemonBackedCommandWithoutStoreAccess(t *testing.T) {
	for _, args := range [][]string{
		{"changepass"},
		{"backup", "list"},
		{"restore", "preview", "archive.tar.gz"},
	} {
		if err := enforceApstoreExecutionMode("/deliberately/inaccessible", args); err != nil {
			t.Fatalf("enforceApstoreExecutionMode(%v) error = %v", args, err)
		}
	}
	if isDaemonBackedCommand([]string{"generations", "prune"}) {
		t.Fatal("generations prune must remain offline")
	}
}

func TestApstoreNoLongerClassifiesMovedCatalogCommandsAsDaemonBacked(t *testing.T) {
	for _, args := range [][]string{
		{"template", "list"},
		{"keytype", "enable", "example-v1"},
		{"sentry", "list"},
		{"endpoint", "export"},
		{"generations", "list"},
	} {
		if isDaemonBackedCommand(args) {
			t.Fatalf("retired apstore command %v remains daemon-backed", args)
		}
	}
}

func TestEnforceApstoreExecutionModeAllowsExternalVerifyWithoutStore(t *testing.T) {
	args := []string{"verify", "/mnt/usb/backup.tar.gz"}
	if !isExternalFileOnlyCommand(args) {
		t.Fatal("verify external archive was not classified as external-file-only")
	}
	if err := enforceApstoreExecutionMode("", args); err != nil {
		t.Fatalf("enforceApstoreExecutionMode(verify) error = %v", err)
	}
}

func TestSudoUserIDs(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		t.Setenv("SUDO_UID", "")
		t.Setenv("SUDO_GID", "")

		_, _, ok, err := sudoUserIDs()
		if err != nil {
			t.Fatalf("sudoUserIDs() error = %v", err)
		}
		if ok {
			t.Fatal("sudoUserIDs() ok = true, want false")
		}
	})

	t.Run("valid", func(t *testing.T) {
		t.Setenv("SUDO_UID", "1000")
		t.Setenv("SUDO_GID", "1001")

		uid, gid, ok, err := sudoUserIDs()
		if err != nil {
			t.Fatalf("sudoUserIDs() error = %v", err)
		}
		if !ok {
			t.Fatal("sudoUserIDs() ok = false, want true")
		}
		if uid != 1000 || gid != 1001 {
			t.Fatalf("sudoUserIDs() = %d:%d, want 1000:1001", uid, gid)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		t.Setenv("SUDO_UID", "not-a-number")
		t.Setenv("SUDO_GID", "1001")

		_, _, _, err := sudoUserIDs()
		if err == nil {
			t.Fatal("sudoUserIDs() error = nil, want invalid uid error")
		}
		if !strings.Contains(err.Error(), "invalid SUDO_UID") {
			t.Fatalf("sudoUserIDs() error = %q, want invalid SUDO_UID", err.Error())
		}
	})
}
