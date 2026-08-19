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
//	apstore generations prune               keep current + newest sealed prior
//	apstore generations prune --all-priors  keep only current (required
//	                                        before passphrase rotation)
func cmdGenerations(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apstore generations prune [--all-priors]")
	}
	switch args[0] {
	case "prune":
		paths := keystorePaths()
		identityID := productIdentityID()
		generational, err := genstore.IsGenerational(paths)
		if err != nil {
			return err
		}
		if !generational {
			return fmt.Errorf("store does not use generation-based storage; this release only supports stores it initialized (restore from a backup archive into a fresh store)")
		}
		retainRollbackParent := true
		switch {
		case len(args) == 1:
		case len(args) == 2 && args[1] == "--all-priors":
			retainRollbackParent = false
		default:
			return fmt.Errorf("usage: apstore generations prune [--all-priors]")
		}
		// Pruning deletes rollback targets; the operator confirms the
		// destructive consequence before any gate that could succeed.
		if retainRollbackParent {
			if !confirmYesNo("Prune deletes sealed prior generations except the rollback target (the current generation's parent). Deleted generations cannot be recovered. Proceed? ") {
				return fmt.Errorf("prune cancelled")
			}
		} else {
			if !confirmYesNo("Prune --all-priors deletes ALL prior generations, including the rollback target for the most recent operation. Rollback becomes impossible and the deletion cannot be undone. Proceed? ") {
				return fmt.Errorf("prune cancelled")
			}
		}
		if !retainRollbackParent {
			if err := validateCurrentGenerationForContent(paths, identityID); err != nil {
				return err
			}
			logInfof("pruning all priors abandons every rollback fallback; validating current generation content first")
		}
		kr, err := readStoreKeyring()
		if err != nil {
			return err
		}
		defer kr.Zero()
		if err := kr.RequireSettled(); err != nil {
			return fmt.Errorf("generation prune blocked: %w", err)
		}
		if !retainRollbackParent {
			if err := verifyCurrentGenerationContentWithKeyring(paths, identityID, kr); err != nil {
				return err
			}
		}
		removed, err := genstore.CollectGarbage(paths, nil, retainRollbackParent, kr)
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
		return fmt.Errorf("unknown generations subcommand %q (use prune; live inventory is `apadmin generations list`)", args[0])
	}
}

func validateCurrentGenerationForContent(paths storepaths.Paths, identityID string) error {
	gen, err := genstore.Resolve(paths)
	if err != nil {
		return err
	}
	if err := genstore.ValidateCurrent(gen); err != nil {
		return fmt.Errorf("refusing to prune: current generation failed validation: %w", err)
	}
	return nil
}

func verifyCurrentGenerationContentWithKeyring(paths storepaths.Paths, identityID string, kr *crypto.Keyring) error {
	templateReport, err := signertemplates.NewManager(paths).RegisterKeystoreTemplates(kr)
	if err != nil {
		return fmt.Errorf("template validation failed: %w", err)
	}
	if defects := templateReport.ContentDefectKeyTypes(); len(defects) > 0 {
		return fmt.Errorf("refusing to prune: %d template/key-type defect(s) in the current generation (first: %s)", len(defects), defects[0])
	}
	scan, err := keys.ScanKeysDirectoryWithKeyringReport(paths, kr)
	if err != nil {
		return fmt.Errorf("key validation failed: %w", err)
	}
	if len(scan.Warnings) > 0 {
		return fmt.Errorf("refusing to prune: %d malformed key file(s) in the current generation (first: %s)", len(scan.Warnings), scan.Warnings[0].Message())
	}
	logInfof("current generation content validated")
	return nil
}
