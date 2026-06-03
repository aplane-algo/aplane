// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
