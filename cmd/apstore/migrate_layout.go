// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"time"

	"github.com/aplane-algo/aplane/internal/storemigrate"
)

// cmdMigrateLayout converts a legacy flat identity store to generation-based
// active storage (docs/ARCH_GENERATIONS.md). Offline only: the daemon must
// be stopped (the store lock enforces it). After migration, binaries without
// generation support reject the store instead of reading stale paths; the
// retired legacy namespaces are kept under .legacy-<timestamp>/ for a manual
// rollback window, and .keystore.premigration preserves the pre-bump
// metadata for the documented downgrade path.
func cmdMigrateLayout(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: apstore migrate-layout")
	}
	result, err := storemigrate.Migrate(keystorePaths(), productIdentityID(), time.Now())
	if err != nil {
		return err
	}
	switch {
	case result.AlreadyMigrated:
		logInfof("store already uses generation-based storage (generation %s); validated", result.GenerationID)
	case result.ResumedAfterCrash:
		logInfof("finished interrupted migration: generation %s", result.GenerationID)
	default:
		logInfof("migrated store to generation-based storage: generation %s", result.GenerationID)
	}
	if result.RetiredDir != "" {
		logInfof("legacy namespaces retained for rollback at %s; remove them once satisfied", result.RetiredDir)
	}
	return nil
}
