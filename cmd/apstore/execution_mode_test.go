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

func TestEnforceApstoreExecutionModeAllowsExternalVerifyWithoutStore(t *testing.T) {
	args := []string{"verify", "/mnt/usb/backup.tar.gz"}
	if !isExternalFileOnlyCommand(args) {
		t.Fatal("verify external archive was not classified as external-file-only")
	}
	if err := enforceApstoreExecutionMode("", args); err != nil {
		t.Fatalf("enforceApstoreExecutionMode(verify) error = %v", err)
	}
}

// The refusals name the exact command to run instead, quoted for a shell.
func TestEnforceApstoreExecutionModeRefusalText(t *testing.T) {
	oldEUID := currentEUID
	t.Cleanup(func() { currentEUID = oldEUID })

	local := filepath.Join(t.TempDir(), "it's local")
	if err := os.Mkdir(local, 0o700); err != nil {
		t.Fatal(err)
	}
	managed := t.TempDir()
	if err := os.WriteFile(filepath.Join(managed, ".prod"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"rebuild", "/mnt/usb/a b.tar.gz", "--address", ""}

	currentEUID = func() int { return 0 }
	err := enforceApstoreExecutionMode(local, args)
	want := "local signer data directory " + local + " must not be managed as root; rerun without sudo:\n" +
		"  apstore -d '" + filepath.Dir(local) + "/it'\"'\"'s local' rebuild '/mnt/usb/a b.tar.gz' --address ''"
	if err == nil || err.Error() != want {
		t.Fatalf("local as root:\n got %v\nwant %s", err, want)
	}

	currentEUID = func() int { return 1000 }
	err = enforceApstoreExecutionMode(managed, args)
	want = "systemd-managed data directory " + managed + " requires root for apstore; run:\n" +
		"  sudo apstore -d " + managed + " rebuild '/mnt/usb/a b.tar.gz' --address ''"
	if err == nil || err.Error() != want {
		t.Fatalf("managed as non-root:\n got %v\nwant %s", err, want)
	}

	currentEUID = func() int { return 0 }
	if err := enforceApstoreExecutionMode(managed, args); err != nil {
		t.Fatalf("managed as root: %v", err)
	}
}

// exitCalled stops dispatchApstoreCommand at its first exit, as os.Exit would.
type exitCalled struct{ code int }

// dispatchUntilExit runs dispatchApstoreCommand with osExit stubbed, and
// returns the code of the first exit and what was logged before it.
func dispatchUntilExit(t *testing.T, args []string) (code int, logged string) {
	t.Helper()
	var log strings.Builder
	appLogger.SetOutput(&log)
	oldExit := osExit
	osExit = func(code int) { panic(exitCalled{code}) }
	t.Cleanup(func() {
		osExit = oldExit
		appLogger.SetOutput(os.Stderr)
	})
	defer func() {
		r := recover()
		exit, ok := r.(exitCalled)
		if !ok {
			panic(r)
		}
		code, logged = exit.code, log.String()
	}()
	dispatchApstoreCommand(args)
	t.Fatalf("dispatch %q returned without exiting", args)
	return 0, ""
}

// The managed-store conversions need root, and only the execution-mode gate
// says so: run without root, each is refused at dispatch before it takes the
// store lock or touches the store.
func TestManagedStorePermissionCommandsRequireRootBeforeTouchingTheStore(t *testing.T) {
	for _, verb := range []string{"prepare-managed-root", "convert-managed"} {
		t.Run(verb, func(t *testing.T) {
			oldDataDirectory, oldEUID, oldMigrate := dataDirectory, currentEUID, migrateManagedStore
			t.Cleanup(func() { dataDirectory, currentEUID, migrateManagedStore = oldDataDirectory, oldEUID, oldMigrate })
			dataDirectory = t.TempDir()
			currentEUID = func() int { return 1000 }
			migrateManagedStore = func(string, int, int, string) error {
				t.Error("the store was migrated")
				return nil
			}

			code, logged := dispatchUntilExit(t, []string{"permissions", verb, "--uid", "1", "--gid", "1"})
			if code != apstoreExitFailure {
				t.Fatalf("exit = %d, want %d", code, apstoreExitFailure)
			}
			want := "[ERROR] permissions " + verb + " requires root\n"
			if !strings.HasPrefix(logged, "apstore ") || !strings.HasSuffix(logged, want) || strings.Count(logged, "\n") != 1 {
				t.Fatalf("logged %q, want one line ending %q", logged, want)
			}
			// The store lock file, the .prod marker, the service principal and
			// any migrated file would all appear in the data directory.
			entries, err := os.ReadDir(dataDirectory)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("the data directory was touched: %v", entries)
			}
		})
	}
}
