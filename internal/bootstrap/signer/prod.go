// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	ProdMarkerFile            = ".prod"
	SystemdManagedInstanceEnv = "APLANE_SYSTEMD_MANAGED"
)

// IsProductionManagedDataDir reports whether dataDir has the systemd-managed
// marker written by the systemd installer.
func IsProductionManagedDataDir(dataDir string) (bool, error) {
	markerPath := filepath.Join(dataDir, ProdMarkerFile)
	if _, err := os.Stat(markerPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("checking managed install marker %s: %w", markerPath, err)
	}
	return true, nil
}

// RunningUnderSystemd reports whether the process appears to be launched by
// systemd or an equivalent service manager PID 1 context.
func RunningUnderSystemd() bool {
	return os.Getenv(SystemdManagedInstanceEnv) == "1" || os.Getppid() == 1
}

// EnforceExecutionMode applies the rule for a binary that manages a signer
// data directory itself: a systemd-managed directory is managed as root, a
// local one never is. A refusal names the command to run instead: binary
// with -d dataDir and args, under sudo or not.
func EnforceExecutionMode(binary, dataDir string, prodManaged bool, euid int, args []string) error {
	switch {
	case prodManaged && euid != 0:
		return fmt.Errorf(
			"systemd-managed data directory %s requires root for %s; run:\n  %s",
			dataDir,
			binary,
			Invocation(binary, true, dataDir, args),
		)
	case !prodManaged && euid == 0:
		return fmt.Errorf(
			"local signer data directory %s must not be managed as root; rerun without sudo:\n  %s",
			dataDir,
			Invocation(binary, false, dataDir, args),
		)
	default:
		return nil
	}
}

// Invocation is the shell command line that runs binary with -d dataDir and
// args, under sudo when useSudo is set, each word quoted for a POSIX shell.
func Invocation(binary string, useSudo bool, dataDir string, args []string) string {
	parts := []string{binary, "-d", dataDir}
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
