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
		return fmt.Errorf("store does not use generation-based storage; this release only supports stores it initialized (restore from a backup archive into a fresh store)")
	}

	switch args[0] {
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("usage: apstore generations list")
		}
		// Read-only: list classifies without deleting. Discard of staging
		// residue and uncommitted attempts happens at unlock or prune.
		report, err := genstore.Inspect(paths, identityID, nil)
		if err != nil {
			return err
		}
		reportPendingDiscards(report)
		if report.RetainedUnsealedParent != "" {
			logWarnf("rollback parent %s is missing its seal; pruning is blocked until it is restored or removed", report.RetainedUnsealedParent)
		}
		logInfof("current: %s", report.Current)
		for _, prior := range report.SealedPriors {
			logInfof("sealed prior: %s", prior)
		}
		if len(report.SealedPriors) == 0 && report.RetainedUnsealedParent == "" {
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
		if !retainRollbackParent {
			if err := verifyCurrentGenerationContent(paths, identityID); err != nil {
				return err
			}
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

// verifyCurrentGenerationContent decrypt-validates the current generation
// with the same checks the signer's fail-closed reload gate applies: a clean
// key scan and no template/key-type content defects. An --all-priors prune
// abandons every rollback fallback, and passphrase rotation — the workflow
// this prune prepares — re-encrypts all of this content next; defects must
// surface while a rollback target still exists.
func verifyCurrentGenerationContent(paths storepaths.Paths, identityID string) error {
	// Structural validation precedes the passphrase prompt and every
	// content read: a symlinked or otherwise malformed namespace must be
	// rejected here, not followed by the scans below (only the structural
	// validator checks that namespace entries are regular files).
	gen, err := genstore.Resolve(paths, identityID)
	if err != nil {
		return err
	}
	if err := genstore.ValidateCurrent(gen); err != nil {
		return fmt.Errorf("refusing to prune: current generation failed validation: %w", err)
	}

	logInfof("pruning all priors abandons every rollback fallback; validating current generation content first")
	fmt.Print("Enter passphrase: ")
	passphrase, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %w", err)
	}
	fmt.Println()
	defer crypto.ZeroBytes(passphrase)

	meta, err := crypto.LoadKeystoreMetadata(paths.KeystoreMetadataDir(identityID))
	if err != nil {
		return fmt.Errorf("failed to load keystore metadata: %w", err)
	}
	masterKey, err := meta.VerifyAndDeriveMasterKey(passphrase)
	if err != nil {
		return fmt.Errorf("passphrase verification failed: %w", err)
	}
	defer crypto.ZeroBytes(masterKey)

	templateReport, err := signertemplates.NewManager(paths).RegisterKeystoreTemplates(identityID, masterKey)
	if err != nil {
		return fmt.Errorf("template validation failed: %w", err)
	}
	if defects := templateReport.ContentDefectKeyTypes(); len(defects) > 0 {
		return fmt.Errorf("refusing to prune: %d template/key-type defect(s) in the current generation (first: %s)", len(defects), defects[0])
	}
	scan, err := keys.ScanKeysDirectoryWithMasterKeyReport(paths, identityID, masterKey)
	if err != nil {
		return fmt.Errorf("key validation failed: %w", err)
	}
	if len(scan.Warnings) > 0 {
		return fmt.Errorf("refusing to prune: %d malformed key file(s) in the current generation (first: %s)", len(scan.Warnings), scan.Warnings[0].Message())
	}
	logInfof("current generation content validated")
	return nil
}

func reportPendingDiscards(report genstore.ReconcileReport) {
	for _, attempt := range report.DiscardedAttempts {
		logInfof("uncommitted generation %s (discarded at next unlock or prune)", attempt)
	}
	for _, staging := range report.DiscardedStaging {
		logInfof("staging residue %s (discarded at next unlock or prune)", staging)
	}
}
