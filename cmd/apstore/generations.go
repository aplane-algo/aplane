// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// cmdGenerations manages generation-based active storage
// (docs/ARCH_GENERATIONS.md). Destructive pruning is offline and requires the
// daemon to stop. Live inventory is owned by `apadmin generations list`.
//
//	apstore generations prune [--yes]               keep current + newest sealed prior
//	apstore generations prune --all-priors [--yes]  keep only current
//
// --yes accepts the destructive-consequence confirmation for unattended runs
// (with APSIGNER_PASSPHRASE for --all-priors); the consequence is still logged.
func cmdGenerations(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", generationsPruneUsage)
	}
	switch args[0] {
	case "prune":
		opts, err := parsePruneArgs(args[1:])
		if err != nil {
			return err
		}
		paths := keystorePaths()
		if !crypto.StoreRootExistsIn(paths.KeystoreMetadataDir()) {
			return fmt.Errorf("store is not initialized with the required atomic store-root layout")
		}
		retainRollbackParent := !opts.allPriors
		// Pruning deletes rollback targets; the operator confirms the
		// destructive consequence before any gate that could succeed.
		consequence := "Prune deletes sealed prior generations except the rollback target (the current generation's parent). Deleted generations cannot be recovered."
		if !retainRollbackParent {
			consequence = "Prune --all-priors deletes ALL prior generations, including the rollback target for the most recent operation. Rollback becomes impossible and the deletion cannot be undone."
		}
		if opts.assumeYes {
			logInfof("%s Confirmed by --yes.", consequence)
		} else if !confirmYesNo(consequence + " Proceed? [y/N]: ") {
			return fmt.Errorf("prune cancelled")
		}
		active, kr, err := readStore()
		if err != nil {
			return err
		}
		defer kr.Zero()
		if !retainRollbackParent {
			logInfof("pruning all priors abandons every rollback fallback; validating current generation content first")
			if err := verifyCurrentGenerationContentWithKeyring(paths, active, kr); err != nil {
				return err
			}
		}
		removed, err := genstore.CollectGarbageStoreRoot(paths, nil, retainRollbackParent, kr)
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
			logInfof("only the current generation remains")
		} else {
			logInfof("the current generation's parent retained as the rollback target")
		}
		return nil

	default:
		return fmt.Errorf("unknown generations subcommand %q (use prune; live inventory is `apadmin generations list`)", args[0])
	}
}

const generationsPruneUsage = "usage: apstore generations prune [--all-priors] [--yes]"

type pruneOptions struct {
	allPriors bool
	assumeYes bool
}

func parsePruneArgs(args []string) (pruneOptions, error) {
	var opts pruneOptions
	seen := make(map[string]bool, len(args))
	for _, arg := range args {
		if seen[arg] {
			return pruneOptions{}, fmt.Errorf("duplicate prune option %s; %s", arg, generationsPruneUsage)
		}
		seen[arg] = true
		switch arg {
		case "--all-priors":
			opts.allPriors = true
		case "--yes":
			opts.assumeYes = true
		default:
			return pruneOptions{}, fmt.Errorf("%s", generationsPruneUsage)
		}
	}
	return opts, nil
}

func validateCurrentGenerationForContent(gen storepaths.GenPaths) error {
	if err := genstore.ValidateCurrent(gen); err != nil {
		return fmt.Errorf("refusing to prune: current generation failed validation: %w", err)
	}
	return nil
}

func verifyCurrentGenerationContentWithKeyring(paths storepaths.Paths, active storepaths.GenPaths, kr *crypto.Keyring) error {
	manager := signertemplates.NewManager(paths)
	manager.ActivePaths = active
	templateReport, err := manager.RegisterKeystoreTemplates(kr)
	if err != nil {
		return fmt.Errorf("template validation failed: %w", err)
	}
	if defects := templateReport.ContentDefectKeyTypes(); len(defects) > 0 {
		return fmt.Errorf("refusing to prune: %d template/key-type defect(s) in the current generation (first: %s)", len(defects), defects[0])
	}
	scan, err := keys.ScanKeysDirectoryWithKeyringReportActive(active, kr)
	if err != nil {
		return fmt.Errorf("key validation failed: %w", err)
	}
	if len(scan.Warnings) > 0 {
		return fmt.Errorf("refusing to prune: %d malformed key file(s) in the current generation (first: %s)", len(scan.Warnings), scan.Warnings[0].Message())
	}
	logInfof("current generation content validated")
	return nil
}
