// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package adminipc owns local admin-socket placement and discovery. It is
// intentionally independent of private signer configuration for the normal
// systemd client path.
package adminipc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	signerbootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
	"github.com/aplane-algo/aplane/internal/serverconfig"
)

const (
	// SystemRuntimeDir is created by systemd's RuntimeDirectory=apsigner.
	SystemRuntimeDir = "/run/apsigner"
	// SystemSocketPath is the stable multi-UID local admin endpoint.
	SystemSocketPath = SystemRuntimeDir + "/aplane.sock"
	// SocketPathEnv provides an explicit deployment override for local clients.
	SocketPathEnv = "APSIGNER_IPC_PATH"
)

// ResolveDaemonPath selects the production runtime socket for a managed
// instance unless config carries a genuinely custom path. Same-UID instances
// retain the data-root socket.
func ResolveDaemonPath(dataDir, configured string, systemdManaged bool) string {
	legacyDefault := filepath.Join(dataDir, "aplane.sock")
	if configured == "" {
		configured = legacyDefault
	}
	if systemdManaged && filepath.Clean(configured) == filepath.Clean(legacyDefault) {
		return SystemSocketPath
	}
	return configured
}

// ResolveClientPath locates the local admin socket without requiring private
// signer-store access. Resolution is explicit flag, environment override,
// established system runtime directory, then readable legacy config/default.
func ResolveClientPath(dataDir, explicit string) (string, error) {
	if explicit != "" {
		return filepath.Clean(explicit), nil
	}
	if fromEnv := os.Getenv(SocketPathEnv); fromEnv != "" {
		return filepath.Clean(fromEnv), nil
	}
	if dataDir != "" {
		path, resolved, err := resolveDataDirectoryPath(dataDir)
		if err != nil {
			return "", err
		}
		if resolved {
			return path, nil
		}
	}
	if info, err := os.Lstat(SystemRuntimeDir); err == nil {
		if err := validateRuntimeDirectory(SystemRuntimeDir, info); err != nil {
			return "", err
		}
		return SystemSocketPath, nil
	} else if !os.IsNotExist(err) && !os.IsPermission(err) {
		return "", fmt.Errorf("inspect system admin runtime path: %w", err)
	}
	return SystemSocketPath, nil
}

// resolveDataDirectoryPath resolves a readable explicitly selected or
// environment-selected signer root before the singleton system runtime path.
// A private managed root deliberately falls through to config-free discovery.
func resolveDataDirectoryPath(dataDir string) (string, bool, error) {
	managed, err := signerbootstrap.IsProductionManagedDataDir(dataDir)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return "", false, nil
		}
		return "", false, err
	}
	configPath := filepath.Join(dataDir, "config.yaml")
	if _, err := os.Lstat(configPath); err != nil {
		if os.IsPermission(err) {
			return "", false, nil
		}
		if os.IsNotExist(err) {
			if managed {
				return SystemSocketPath, true, nil
			}
			return filepath.Join(dataDir, "aplane.sock"), true, nil
		}
		return "", false, fmt.Errorf("inspect signer config for IPC discovery: %w", err)
	}

	cfg, err := serverconfig.LoadServerConfig(dataDir)
	if err != nil {
		return "", false, err
	}
	return filepath.Clean(ResolveDaemonPath(dataDir, cfg.IPCPath, managed)), true, nil
}

func validateRuntimeDirectory(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("system admin runtime path is not a real directory: %s", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("system admin runtime path is group/other writable: %s", path)
	}
	return nil
}
