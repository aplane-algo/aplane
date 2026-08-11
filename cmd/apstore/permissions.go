// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/aplane-algo/aplane/internal/adminipc"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	"github.com/aplane-algo/aplane/internal/storeperm"
)

func cmdPermissions(args []string) error {
	if len(args) == 0 {
		return permissionsUsageError()
	}
	if args[0] == "convert-managed" {
		return cmdPermissionsConvertManaged(args[1:])
	}
	if len(args) != 1 || (args[0] != "preflight" && args[0] != "audit" && args[0] != "migrate") {
		return permissionsUsageError()
	}
	if args[0] == "preflight" {
		result, err := storeperm.PreflightLegacy(dataDirectory)
		if err != nil {
			return err
		}
		logInfof("legacy store structural preflight passed: inspected %d object(s)", result.Inspected)
		return nil
	}
	managed, err := signerstartup.IsProductionManagedDataDir(dataDirectory)
	if err != nil {
		return err
	}
	if args[0] == "migrate" && !managed {
		return fmt.Errorf("permissions migrate is only supported for systemd-managed signer stores")
	}
	uid, gid, err := storePermissionOwner(dataDirectory, managed)
	if err != nil {
		return err
	}
	if args[0] == "migrate" {
		socketPath, err := configuredMigrationSocketPath(dataDirectory)
		if err != nil {
			return err
		}
		opts := storeperm.LegacyMigrationOptions(dataDirectory, uid, gid, socketPath)
		result, err := storeperm.MigratePrivate(opts)
		if err != nil {
			return err
		}
		logInfof("private store migration complete: inspected %d object(s), changed %d", result.Inspected, result.Changed)
		return nil
	}
	var opts storeperm.AuditOptions
	if managed {
		opts = storeperm.ProductionAuditOptions(dataDirectory, uid, gid)
	} else {
		socketPath, err := configuredLiveAuditSocketPath(dataDirectory)
		if err != nil {
			return err
		}
		opts = storeperm.SameUIDAuditOptions(dataDirectory, uid, gid, socketPath)
	}
	findings, err := storeperm.Audit(opts)
	if err != nil {
		return err
	}
	if len(findings) != 0 {
		for _, finding := range findings {
			logErrorf("%s", finding.Error())
		}
		return fmt.Errorf("private store permission audit failed with %d finding(s)", len(findings))
	}
	logInfof("private store permission audit passed")
	return nil
}

func permissionsUsageError() error {
	return fmt.Errorf("usage: apstore permissions <preflight|audit|migrate|convert-managed --uid UID --gid GID>")
}

func cmdPermissionsConvertManaged(args []string) error {
	flags := flag.NewFlagSet("permissions convert-managed", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	uidText := flags.String("uid", "", "numeric service uid")
	gidText := flags.String("gid", "", "numeric service gid")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *uidText == "" || *gidText == "" {
		return permissionsUsageError()
	}
	uid, err := strconv.Atoi(*uidText)
	if err != nil || uid <= 0 {
		return fmt.Errorf("invalid managed service uid %q", *uidText)
	}
	gid, err := strconv.Atoi(*gidText)
	if err != nil || gid < 0 {
		return fmt.Errorf("invalid managed service gid %q", *gidText)
	}
	if currentEUID() != 0 {
		return fmt.Errorf("permissions convert-managed requires root")
	}
	if _, err := storeperm.PreflightLegacy(dataDirectory); err != nil {
		return err
	}
	socketPath, err := configuredMigrationSocketPath(dataDirectory)
	if err != nil {
		return err
	}
	result, err := storeperm.MigratePrivate(storeperm.LegacyMigrationOptions(dataDirectory, uid, gid, socketPath))
	if err != nil {
		return err
	}
	if err := storeperm.PublishManagedMetadata(dataDirectory, uid, gid); err != nil {
		return err
	}
	findings, err := storeperm.Audit(storeperm.ProductionAuditOptions(dataDirectory, uid, gid))
	if err != nil {
		return err
	}
	if len(findings) != 0 {
		return fmt.Errorf("managed signer-store verification failed after conversion: %w", findings[0])
	}
	logInfof("managed store conversion complete: inspected %d object(s), changed %d", result.Inspected, result.Changed)
	return nil
}

func configuredLiveAuditSocketPath(root string) (string, error) {
	cfg, err := serverconfig.LoadServerConfig(root)
	if err != nil {
		return "", fmt.Errorf("load signer config for permission audit: %w", err)
	}
	path, managed, err := adminipc.ResolveDaemonPathForDataDir(root, cfg.IPCPath)
	if err != nil {
		return "", fmt.Errorf("resolve signer socket for permission audit: %w", err)
	}
	if managed {
		return "", fmt.Errorf("same-UID permission audit unexpectedly resolved a managed store")
	}
	return path, nil
}

func configuredMigrationSocketPath(root string) (string, error) {
	cfg, err := serverconfig.LoadServerConfig(root)
	if err != nil {
		return "", fmt.Errorf("load signer config for permission migration: %w", err)
	}
	path, err := adminipc.ResolveLegacyStoreSocketPath(root, cfg.IPCPath)
	if err != nil {
		return "", fmt.Errorf("resolve legacy signer socket for permission migration: %w", err)
	}
	return path, nil
}

var managedStoreOwner = storeperm.ManagedServiceOwner

func storePermissionOwner(root string, managed bool) (int, int, error) {
	if managed {
		uid, gid, err := managedStoreOwner(root)
		if err != nil {
			return 0, 0, fmt.Errorf(
				"resolve managed signer service principal: %w; rerun the systemd installer or systemd-setup before permissions audit/migrate",
				err,
			)
		}
		return uid, gid, nil
	}
	info, err := os.Lstat(root)
	if err != nil {
		return 0, 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return 0, 0, fmt.Errorf("signer data directory is not a real directory: %s", root)
	}
	uid, gid, err := fileOwnerGroup(info)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}
