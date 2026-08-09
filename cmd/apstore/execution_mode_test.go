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

func TestAcquireOfflineMutationLockForArgsSkipsIPCTemplateCommands(t *testing.T) {
	dataDir := t.TempDir()

	guard, err := storelock.AcquireExclusive(dataDir)
	if err != nil {
		t.Fatalf("AcquireExclusive() error = %v", err)
	}
	defer func() { _ = guard.Close() }()

	for _, args := range [][]string{
		{"template", "list"},
		{"template", "show", "example-v1", "--show-sensitive-template"},
		{"template", "import", "template.yaml"},
		{"template", "remove", "example-v1"},
	} {
		release, err := acquireOfflineMutationLockForArgs(args, dataDir)
		if err != nil {
			t.Fatalf("acquireOfflineMutationLockForArgs(%v) error = %v", args, err)
		}
		release()
	}
}

func TestAcquireOfflineMutationLockForArgsDoesNotLockIPCKeyTypeCommands(t *testing.T) {
	dataDir := t.TempDir()

	guard, err := storelock.AcquireExclusive(dataDir)
	if err != nil {
		t.Fatalf("AcquireExclusive() error = %v", err)
	}
	defer func() { _ = guard.Close() }()

	for _, args := range [][]string{
		{"keytype", "enable", "example-v1"},
		{"keytype", "disable", "example-v1"},
	} {
		release, err := acquireOfflineMutationLockForArgs(args, dataDir)
		if err != nil {
			t.Fatalf("acquireOfflineMutationLockForArgs(%v) error = %v", args, err)
		}
		release()
	}
}

func TestEnforceApstoreExecutionModeRejectsRootForLocalDataDir(t *testing.T) {
	oldCurrentEUID := currentEUID
	defer func() {
		currentEUID = oldCurrentEUID
	}()

	dataDir := t.TempDir()
	currentEUID = func() int { return 0 }

	err := enforceApstoreExecutionMode(dataDir, []string{"verify", "backup.tar.gz"})
	if err == nil {
		t.Fatal("enforceApstoreExecutionMode() error = nil, want local root refusal")
	}
	for _, want := range []string{
		"local signer data directory",
		"must not be managed as root",
		"apstore -d " + dataDir + " verify backup.tar.gz",
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

	err := enforceApstoreExecutionMode(dataDir, []string{"verify", "backup.tar.gz"})
	if err == nil {
		t.Fatal("enforceApstoreExecutionMode() error = nil, want production non-root refusal")
	}
	for _, want := range []string{
		"systemd-managed data directory",
		"requires root",
		"sudo apstore -d " + dataDir + " verify backup.tar.gz",
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
		{"template", "list"},
		{"keytype", "list"},
		{"backup", "list"},
		{"restore", "preview", "archive.tar.gz"},
		{"sentry", "list"},
		{"sentry", "import", "public.json", "lab"},
		{"generations", "list"},
	} {
		if err := enforceApstoreExecutionMode("/deliberately/inaccessible", args); err != nil {
			t.Fatalf("enforceApstoreExecutionMode(%v) error = %v", args, err)
		}
	}
	if isDaemonBackedCommand([]string{"generations", "prune"}) {
		t.Fatal("generations prune must remain offline")
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

func TestNormalizeManagedStoreOwnershipPreservesSystemdCredOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned systemd credential fixture")
	}
	dataDir := t.TempDir()
	identityDir := filepath.Join(dataDir, "identities", productIdentityID())
	if err := os.MkdirAll(identityDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(identityDir) error = %v", err)
	}
	lockPath := filepath.Join(dataDir, ".apstore.lock")
	if err := os.WriteFile(lockPath, []byte("lock"), 0o600); err != nil {
		t.Fatalf("WriteFile(lock) error = %v", err)
	}
	credPath := filepath.Join(identityDir, "passphrase.cred")
	if err := os.WriteFile(credPath, []byte("cred"), 0o600); err != nil {
		t.Fatalf("WriteFile(cred) error = %v", err)
	}
	if err := os.Chown(credPath, 0, 0); err != nil {
		t.Fatalf("Chown(cred) error = %v", err)
	}

	if err := normalizeManagedStoreOwnership(dataDir); err != nil {
		t.Fatalf("normalizeManagedStoreOwnership() error = %v", err)
	}

	info, err := os.Stat(lockPath)
	if err != nil {
		t.Fatalf("Stat(lock) error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("lock mode = %04o, want 0600", got)
	}
	if _, err := os.Stat(credPath); err != nil {
		t.Fatalf("Stat(cred) error = %v", err)
	}
}

func TestNormalizeManagedStoreOwnershipRejectsSymlink(t *testing.T) {
	dataDir := t.TempDir()
	identityDir := filepath.Join(dataDir, "identities", productIdentityID())
	if err := os.MkdirAll(identityDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(identityDir) error = %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatalf("WriteFile(outside) error = %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(identityDir, "planted")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	err := normalizeManagedStoreOwnership(dataDir)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("normalizeManagedStoreOwnership() error = %v, want symlink rejection", err)
	}
	data, err := os.ReadFile(outside)
	if err != nil {
		t.Fatalf("ReadFile(outside) error = %v", err)
	}
	if string(data) != "unchanged" {
		t.Fatalf("outside contents = %q, want unchanged", data)
	}
}
