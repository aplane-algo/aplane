// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotationinventory

import (
	"fmt"
	"math"
	"os"
	"slices"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// StartRotation performs the pre-append K8 gate and atomically commits the
// pending cryptographic root. The caller holds the identity mutation lock and
// has reconciled generation/recovered staging residue.
//
// This function starts the durable window only. Rewrap, completion-baseline
// publication, close, and snapshot cleanup are separate later phases.
func StartRotation(
	paths storepaths.Paths,
	identityID string,
	kr *crypto.Keyring,
	passphrase []byte,
) (*Snapshot, error) {
	if kr == nil {
		return nil, fmt.Errorf("start rotation: keyring is required")
	}
	if _, pending := kr.PendingRotation(); pending {
		return nil, crypto.ErrRotationAlreadyPending
	}
	if kr.CurrentTerm() == math.MaxInt64 {
		return nil, fmt.Errorf("start rotation: current term is exhausted")
	}

	current, err := genstore.ReadCurrent(paths, identityID)
	if err != nil {
		return nil, fmt.Errorf("start rotation CURRENT: %w", err)
	}
	baseline, err := ReconcileBaselineForPreflight(
		paths,
		identityID,
		current,
		kr,
	)
	if err != nil {
		return nil, err
	}
	report, err := ScanForSnapshot(paths, identityID, kr)
	if err != nil {
		return nil, err
	}
	if report.currentManifest == nil {
		return nil, fmt.Errorf("start rotation scan did not retain current manifest")
	}
	manifest := report.currentManifest
	rollbackEligible := manifest.ParentID != "" && manifest.SourceRestoreID != ""
	if baseline != nil && !rollbackEligible {
		return nil, fmt.Errorf(
			"rotation baseline names current generation %s, which is not rollback-eligible",
			current,
		)
	}
	var rollback *RollbackCutover
	if rollbackEligible {
		rollback, err = EvaluateRollbackCutover(
			current,
			report.currentInventory,
			manifest,
			baseline,
		)
		if err != nil {
			return nil, err
		}
	}

	anchors, err := collectHistoricalAnchors(paths, identityID, current, kr)
	if err != nil {
		return nil, err
	}
	var snapshot *Snapshot
	err = crypto.StartRotation(
		paths.IdentityDir(identityID),
		kr,
		passphrase,
		anchors,
		func(target *crypto.Keyring, fromTerm, toTerm int64) (crypto.RotationSnapshotReference, error) {
			var buildErr error
			snapshot, buildErr = NewSnapshot(report, fromTerm, toTerm, rollback)
			if buildErr != nil {
				return crypto.RotationSnapshotReference{}, buildErr
			}
			return WriteSnapshot(paths, identityID, snapshot, target)
		},
	)
	if err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func collectHistoricalAnchors(
	paths storepaths.Paths,
	identityID, current string,
	kr *crypto.Keyring,
) ([]crypto.HistoricalGenerationAnchor, error) {
	anchors := kr.HistoricalGenerationAnchors()
	byGeneration := make(map[string]crypto.HistoricalGenerationAnchor, len(anchors))
	for _, anchor := range anchors {
		byGeneration[anchor.GenerationID] = anchor
	}

	entries, err := os.ReadDir(paths.GenerationsDir(identityID))
	if err != nil {
		return nil, fmt.Errorf("collect historical anchors: %w", err)
	}
	for _, entry := range entries {
		generationID := entry.Name()
		if strings.HasPrefix(generationID, storepaths.GenerationStagingPrefix) {
			return nil, fmt.Errorf(
				"collect historical anchors found staging residue %q",
				generationID,
			)
		}
		if err := storepaths.ValidateGenerationID(generationID); err != nil {
			return nil, fmt.Errorf(
				"collect historical anchors unexpected generation %q: %w",
				generationID,
				err,
			)
		}
		if !entry.IsDir() {
			return nil, fmt.Errorf(
				"collect historical anchors generation is not a directory: %s",
				generationID,
			)
		}
		if generationID == current {
			continue
		}
		if _, exists := byGeneration[generationID]; exists {
			continue
		}
		anchor, err := genstore.BuildHistoricalAnchor(
			paths.GenerationPaths(identityID, generationID),
			kr,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"collect historical anchor for generation %s: %w",
				generationID,
				err,
			)
		}
		anchors = append(anchors, anchor)
		byGeneration[generationID] = anchor
	}
	slices.SortFunc(anchors, func(a, b crypto.HistoricalGenerationAnchor) int {
		return strings.Compare(a.GenerationID, b.GenerationID)
	})
	return anchors, nil
}
