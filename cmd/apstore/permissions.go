// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/adminipc"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/storeperm"
)

func cmdPermissions(args []string) error {
	if len(args) != 1 || (args[0] != "audit" && args[0] != "migrate") {
		return fmt.Errorf("usage: apstore permissions <audit|migrate>")
	}
	opts, err := storePermissionOptions(dataDirectory)
	if err != nil {
		return err
	}
	if args[0] == "migrate" {
		socketPath, err := configuredMigrationSocketPath(dataDirectory)
		if err != nil {
			return err
		}
		opts.SocketPath = socketPath
		result, err := storeperm.MigratePrivate(opts)
		if err != nil {
			return err
		}
		logInfof("private store migration complete: inspected %d object(s), changed %d", result.Inspected, result.Changed)
		return nil
	}
	opts.Profile = storeperm.PrivateServiceProfile
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

func storePermissionOptions(root string) (storeperm.Options, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return storeperm.Options{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return storeperm.Options{}, fmt.Errorf("signer data directory is not a real directory: %s", root)
	}
	uid, gid, err := fileOwnerGroup(info)
	if err != nil {
		return storeperm.Options{}, err
	}
	return storeperm.Options{Root: root, ExpectedUID: uid, ExpectedGID: gid}, nil
}
