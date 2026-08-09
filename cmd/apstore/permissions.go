// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/adminipc"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	"github.com/aplane-algo/aplane/internal/storeperm"
)

func cmdPermissions(args []string) error {
	if len(args) != 1 || (args[0] != "audit" && args[0] != "migrate") {
		return fmt.Errorf("usage: apstore permissions <audit|migrate>")
	}
	uid, gid, err := storePermissionOwner(dataDirectory)
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
	managed, err := signerstartup.IsProductionManagedDataDir(dataDirectory)
	if err != nil {
		return err
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

func storePermissionOwner(root string) (int, int, error) {
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
