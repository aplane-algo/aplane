// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"github.com/aplane-algo/aplane/internal/security"
)

// lockMemory is a wrapper for the shared security.LockMemory function
func lockMemory() error {
	return security.LockMemory()
}

// disableCoreDumps is a wrapper for the shared security.DisableCoreDumps function
func disableCoreDumps() error {
	return security.DisableCoreDumps()
}
