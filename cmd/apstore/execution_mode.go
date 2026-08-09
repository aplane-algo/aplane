// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	"github.com/aplane-algo/aplane/internal/storelock"
	"github.com/aplane-algo/aplane/internal/storeperm"
)

var currentEUID = os.Geteuid

func runStoreMutatingCommand(command string, fn func() error) error {
	runErr := fn()
	normalizeErr := normalizeProductionStoreAfterRootMutation(command)
	if runErr != nil {
		if normalizeErr != nil {
			return errors.Join(runErr, normalizeErr)
		}
		return runErr
	}
	return normalizeErr
}

func normalizeProductionStoreAfterRootMutation(command string) error {
	if currentEUID() != 0 || !isOfflineMutatingCommand(command) {
		return nil
	}
	prodManaged, err := signerstartup.IsProductionManagedDataDir(dataDirectory)
	if err != nil || !prodManaged {
		return err
	}
	if err := normalizeManagedStoreOwnership(dataDirectory); err != nil {
		return fmt.Errorf("failed to normalize managed store ownership after %s: %w", command, err)
	}
	return nil
}

func normalizeManagedStoreOwnership(dataDir string) error {
	info, err := os.Lstat(dataDir)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("managed data directory is not a real directory: %s", dataDir)
	}
	uid, gid, err := fileOwnerGroup(info)
	if err != nil {
		return err
	}
	socketPath := filepath.Join(dataDir, "aplane.sock")
	prodManaged, prodErr := signerstartup.IsProductionManagedDataDir(dataDir)
	if prodErr != nil {
		return prodErr
	}
	var opts storeperm.MigrationOptions
	if !prodManaged {
		opts = storeperm.TrustedBoundaryMigrationOptions(
			dataDir, uid, gid, socketPath, filepath.Dir(dataDir),
		)
	} else {
		opts = storeperm.LegacyMigrationOptions(dataDir, uid, gid, socketPath)
	}
	_, err = storeperm.MigratePrivate(opts)
	return err
}

func enforceApstoreExecutionMode(dataDir string, args []string) error {
	if isDaemonBackedCommand(args) {
		return nil
	}
	prodManaged, err := signerstartup.IsProductionManagedDataDir(dataDir)
	if err != nil {
		return err
	}
	switch {
	case prodManaged && currentEUID() != 0:
		return fmt.Errorf(
			"systemd-managed data directory %s requires root for apstore; run:\n  %s",
			dataDir,
			apstoreInvocation(true, dataDir, args),
		)
	case !prodManaged && currentEUID() == 0:
		return fmt.Errorf(
			"local signer data directory %s must not be managed as root; rerun without sudo:\n  %s",
			dataDir,
			apstoreInvocation(false, dataDir, args),
		)
	case !prodManaged && currentEUID() != 0:
		return requireLocalDataDirOwnedByCurrentUser(dataDir, args)
	default:
		return nil
	}
}

func isDaemonBackedCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "backup":
		return isManagedBackupCommand(args)
	case "restore":
		return isManagedRestoreCommand(args)
	case "changepass", "template", "keytype":
		return true
	case "sentry":
		return true
	case "generations":
		return len(args) == 2 && args[1] == "list"
	default:
		return false
	}
}

func requireLocalDataDirOwnedByCurrentUser(dataDir string, args []string) error {
	info, err := os.Stat(dataDir)
	if err != nil {
		return fmt.Errorf("cannot stat data directory %s: %w", dataDir, err)
	}
	uid, _, err := fileOwnerGroup(info)
	if err != nil {
		return err
	}
	if uid == currentEUID() {
		return nil
	}
	return fmt.Errorf(
		"local signer data directory %s is owned by uid %d, but current effective uid is %d; "+
			"fix ownership, or restore the systemd-managed .prod marker and run:\n  %s",
		dataDir,
		uid,
		currentEUID(),
		apstoreInvocation(true, dataDir, args),
	)
}

func apstoreInvocation(useSudo bool, dataDir string, args []string) string {
	parts := []string{"apstore", "-d", dataDir}
	if useSudo {
		parts = append([]string{"sudo"}, parts...)
	}
	parts = append(parts, args...)
	for i := range parts {
		parts[i] = shellQuoteArg(parts[i])
	}
	return strings.Join(parts, " ")
}

func isShellSafeRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	}
	return strings.ContainsRune("@%_+=:,./-", r)
}

func shellQuoteArg(s string) string {
	if s == "" {
		return "''"
	}
	for _, r := range s {
		if isShellSafeRune(r) {
			continue
		}
		return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
	}
	return s
}

func isOfflineMutatingCommand(command string) bool {
	switch command {
	case "initialize", "policy", "rebuild", "generations", "permissions":
		return true
	default:
		return false
	}
}

func isManagedBackupCommand(args []string) bool {
	if len(args) < 2 || args[0] != "backup" {
		return false
	}
	switch args[1] {
	case "create", "import", "list", "export", "delete":
		return true
	default:
		return false
	}
}

func isManagedRestoreCommand(args []string) bool {
	if len(args) < 2 || args[0] != "restore" {
		return false
	}
	switch args[1] {
	case "preview", "apply", "rollback", "reconcile":
		return true
	default:
		return false
	}
}

func acquireOfflineMutationLockForArgs(args []string, dataDir string) (func(), error) {
	if isManagedBackupCommand(args) || isManagedRestoreCommand(args) {
		return func() {}, nil
	}
	if len(args) == 0 {
		return func() {}, nil
	}
	if isStorePermissionCommand(args) && len(args) == 2 && args[1] == "audit" {
		return func() {}, nil
	}
	if args[0] == "policy" {
		if len(args) > 1 && args[1] == "sign" {
			return acquireOfflineMutationLock("policy", dataDir)
		}
		return func() {}, nil
	}
	if args[0] == "template" || args[0] == "keytype" {
		return func() {}, nil
	}
	if args[0] == "generations" && len(args) == 2 && args[1] == "list" {
		return func() {}, nil
	}
	return acquireOfflineMutationLock(args[0], dataDir)
}

func isStorePermissionCommand(args []string) bool {
	return len(args) > 0 && args[0] == "permissions"
}

func acquireOfflineMutationLock(command, dataDir string) (func(), error) {
	switch {
	case isOfflineMutatingCommand(command):
		guard, err := storelock.AcquireExclusive(dataDir)
		if err != nil {
			if errors.Is(err, storelock.ErrBusy) {
				return nil, fmt.Errorf("refusing to run local bootstrap/rescue command %q while apsigner or another apstore mutation holds the store lock", command)
			}
			return nil, err
		}
		return func() { _ = guard.Close() }, nil
	default:
		return func() {}, nil
	}
}

func sudoUserIDs() (int, int, bool, error) {
	uidText := os.Getenv("SUDO_UID")
	gidText := os.Getenv("SUDO_GID")
	if uidText == "" || gidText == "" {
		return 0, 0, false, nil
	}
	uid, err := strconv.Atoi(uidText)
	if err != nil {
		return 0, 0, false, fmt.Errorf("invalid SUDO_UID %q: %w", uidText, err)
	}
	gid, err := strconv.Atoi(gidText)
	if err != nil {
		return 0, 0, false, fmt.Errorf("invalid SUDO_GID %q: %w", gidText, err)
	}
	if uid < 0 || gid < 0 {
		return 0, 0, false, fmt.Errorf("invalid sudo ownership %d:%d", uid, gid)
	}
	return uid, gid, true, nil
}

func fileOwnerGroup(info os.FileInfo) (int, int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("could not determine file ownership")
	}
	return int(stat.Uid), int(stat.Gid), nil
}
