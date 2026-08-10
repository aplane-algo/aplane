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
	"strings"

	signerbootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
	"github.com/aplane-algo/aplane/internal/serverconfig"
)

const (
	// SystemDataDir is the conventional private store paired with the
	// singleton system runtime socket. Custom managed stores must provide an
	// explicit IPC path when their private root cannot be inspected.
	SystemDataDir = "/var/lib/apsigner"
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
	} else if !filepath.IsAbs(configured) {
		configured = filepath.Join(dataDir, configured)
	}
	configured = filepath.Clean(configured)
	if systemdManaged && filepath.Clean(configured) == filepath.Clean(legacyDefault) {
		return SystemSocketPath
	}
	return configured
}

// ResolveDaemonPathForDataDir derives managed placement from the durable
// store marker, which is also the source used by clients. Process-environment
// signals authorize a managed launch but do not define the store's identity.
func ResolveDaemonPathForDataDir(dataDir, configured string) (string, bool, error) {
	managed, err := signerbootstrap.IsProductionManagedDataDir(dataDir)
	if err != nil {
		return "", false, err
	}
	resolved := ResolveDaemonPath(dataDir, configured, managed)
	if err := validateManagedDaemonPath(dataDir, resolved, managed); err != nil {
		return "", managed, err
	}
	return resolved, managed, nil
}

// ResolveLegacyStoreSocketPath returns the one exact in-store socket that a
// stopped migration may remove. A configured in-store path supports upgrades
// from releases that allowed it; an external custom path leaves only the
// historical default eligible for cleanup.
func ResolveLegacyStoreSocketPath(dataDir, configured string) (string, error) {
	configured = ResolveDaemonPath(dataDir, configured, false)
	inside, err := pathWithin(dataDir, configured)
	if err != nil {
		return "", err
	}
	if inside {
		return configured, nil
	}
	return filepath.Clean(filepath.Join(dataDir, "aplane.sock")), nil
}

func validateManagedDaemonPath(dataDir, resolved string, managed bool) error {
	if !managed {
		return nil
	}
	inside, err := pathWithin(dataDir, resolved)
	if err != nil {
		return err
	}
	if inside {
		return fmt.Errorf(
			"systemd-managed admin IPC path must be outside signer data directory: %s; use %s or another service-owned protected runtime directory",
			resolved, SystemSocketPath,
		)
	}
	return nil
}

func pathWithin(root, candidate string) (bool, error) {
	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return false, fmt.Errorf("resolve signer data directory: %w", err)
	}
	candidateAbs, err := filepath.Abs(filepath.Clean(candidate))
	if err != nil {
		return false, fmt.Errorf("resolve admin IPC path: %w", err)
	}
	rel, err := filepath.Rel(rootAbs, candidateAbs)
	if err != nil {
		return false, fmt.Errorf("compare admin IPC path with signer data directory: %w", err)
	}
	return rel != ".." && !filepath.IsAbs(rel) && !strings.HasPrefix(rel, ".."+string(filepath.Separator)), nil
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
// Only the conventional private system store may fall through to config-free
// discovery. A custom selected root must never silently retarget its client to
// the singleton system signer.
func resolveDataDirectoryPath(dataDir string) (string, bool, error) {
	if _, err := os.Lstat(dataDir); err != nil {
		if os.IsPermission(err) {
			return privateDataDirectoryFallback(dataDir, err)
		}
		if os.IsNotExist(err) {
			return "", false, fmt.Errorf(
				"selected signer data directory does not exist: %s (unset APSIGNER_DATA or select an existing directory)",
				dataDir,
			)
		}
		return "", false, fmt.Errorf("inspect selected signer data directory: %w", err)
	}
	managed, err := signerbootstrap.IsProductionManagedDataDir(dataDir)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return privateDataDirectoryFallback(dataDir, err)
		}
		return "", false, err
	}
	configPath := filepath.Join(dataDir, "config.yaml")
	if _, err := os.Lstat(configPath); err != nil {
		if os.IsPermission(err) {
			return privateDataDirectoryFallback(dataDir, err)
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
	resolved := ResolveDaemonPath(dataDir, cfg.IPCPath, managed)
	if err := validateManagedDaemonPath(dataDir, resolved, managed); err != nil {
		return "", false, err
	}
	return resolved, true, nil
}

func privateDataDirectoryFallback(dataDir string, cause error) (string, bool, error) {
	abs, err := filepath.Abs(filepath.Clean(dataDir))
	if err == nil && abs == SystemDataDir {
		return "", false, nil
	}
	return "", false, fmt.Errorf(
		"cannot inspect selected signer data directory %s: %w; refusing to fall back to %s for a different store (set %s only when that socket is the intended signer)",
		dataDir, cause, SystemSocketPath, SocketPathEnv,
	)
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
