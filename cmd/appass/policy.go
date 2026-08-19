// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

func managedModePolicyPaths(dataDir string) []string {
	identityDir := storepaths.NewPaths(dataDir).ProductDir()
	return []string{
		filepath.Join(dataDir, "config.yaml"),
		filepath.Join(identityDir, "unlock.yaml"),
		filepath.Join(identityDir, "passphrase"),
		filepath.Join(identityDir, "passphrase.cred"),
	}
}

func enforceModeOwnershipPolicy(dataDir string, isLocal bool, svc *serviceInfo) error {
	for _, path := range managedModePolicyPaths(dataDir) {
		owner, err := lookupFileOwner(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if err := validateManagedFileOwner(dataDir, path, owner, isLocal, svc); err != nil {
			return err
		}
	}

	return nil
}

func validateManagedFileOwner(dataDir, path, owner string, isLocal bool, svc *serviceInfo) error {
	if isLocal {
		expected := currentUsername()
		if owner != expected {
			if owner == "aplane" {
				return fmt.Errorf("%s is owned by %s; this looks like a systemd-managed signer data directory.\n\nSystemd installs should run appass as root:\n  1. sudo systemctl stop apsigner\n  2. sudo appass -d %s\n  3. sudo systemctl start apsigner", path, owner, dataDir)
			}
			return fmt.Errorf("%s is owned by %s; local and systemd-managed data directories must not be mixed (expected local owner %s)", path, owner, expected)
		}
		return nil
	}

	if owner != "root" && (svc == nil || owner != svc.User) {
		allowed := []string{"root"}
		if svc != nil && svc.User != "" {
			allowed = append(allowed, svc.User)
		}
		return fmt.Errorf("%s is owned by %s; systemd mode only supports files owned by %s", path, owner, strings.Join(allowed, " or "))
	}

	return nil
}

func lookupFileOwner(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("could not determine file owner for %s", path)
	}

	u, err := user.LookupId(strconv.FormatUint(uint64(stat.Uid), 10))
	if err != nil {
		return "", fmt.Errorf("looking up owner for %s: %w", path, err)
	}

	return u.Username, nil
}
