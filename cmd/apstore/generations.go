// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/genstore"
)

// cmdGenerations manages generation-based active storage
// (docs/ARCH_GENERATIONS.md). Offline only: the daemon must be stopped (the
// store lock enforces it).
//
//	apstore generations list                 inventory with roles
//	apstore generations prune               keep current + newest sealed prior
//	apstore generations prune --all-priors  keep only current (required
//	                                        before passphrase rotation)
func cmdGenerations(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apstore generations <list|prune [--all-priors]>")
	}
	paths := keystorePaths()
	identityID := productIdentityID()

	generational, err := genstore.IsGenerational(paths, identityID)
	if err != nil {
		return err
	}
	if !generational {
		return fmt.Errorf("store does not use generation-based storage (run apstore migrate-layout to convert)")
	}

	switch args[0] {
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("usage: apstore generations list")
		}
		report, err := genstore.Reconcile(paths, identityID, nil)
		if err != nil {
			return err
		}
		reportDiscards(report)
		logInfof("current: %s", report.Current)
		for _, prior := range report.SealedPriors {
			logInfof("sealed prior: %s", prior)
		}
		if len(report.SealedPriors) == 0 {
			logInfof("no prior generations (rotation quiescence satisfied)")
		}
		return nil

	case "prune":
		retainRollbackParent := true
		switch {
		case len(args) == 1:
		case len(args) == 2 && args[1] == "--all-priors":
			retainRollbackParent = false
		default:
			return fmt.Errorf("usage: apstore generations prune [--all-priors]")
		}
		removed, err := genstore.CollectGarbage(paths, identityID, nil, retainRollbackParent)
		if err != nil {
			return err
		}
		for _, name := range removed {
			logInfof("removed generation %s", name)
		}
		if len(removed) == 0 {
			logInfof("nothing to prune")
		}
		if !retainRollbackParent {
			logInfof("only the current generation remains; passphrase rotation quiescence satisfied")
		} else {
			logInfof("the current generation's parent retained as the rollback target")
		}
		return nil

	default:
		return fmt.Errorf("unknown generations subcommand %q (use list or prune)", args[0])
	}
}

func reportDiscards(report genstore.ReconcileReport) {
	for _, discarded := range report.DiscardedAttempts {
		logInfof("discarded uncommitted generation %s", discarded)
	}
	for _, staging := range report.DiscardedStaging {
		logInfof("discarded staging residue %s", staging)
	}
}
