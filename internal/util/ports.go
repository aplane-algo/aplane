// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"os"
	"path/filepath"
)

// Default port constants for Signer services
const (
	// DefaultRESTPort is the default HTTP REST API port for Signer
	DefaultRESTPort = 11270

	// DefaultSSHPort is the default SSH tunnel port for Signer
	DefaultSSHPort = 1127
)

// GetDefaultIPCPath returns the default Unix socket path for IPC.
// Priority order:
//  1. $APSIGNER_DATA/aplane.sock (if APSIGNER_DATA is set)
//  2. /tmp/aplane.sock (fallback)
func GetDefaultIPCPath() string {
	// Try APSIGNER_DATA if set
	if signerData := os.Getenv("APSIGNER_DATA"); signerData != "" {
		return filepath.Join(signerData, "aplane.sock")
	}

	// Last resort
	return "/tmp/aplane.sock"
}
