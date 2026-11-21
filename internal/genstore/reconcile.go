// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// ReconcileReport records what startup reconciliation found and changed.
type ReconcileReport struct {
	Current string
	// Quarantined are safely relocatable, published-but-uncommitted
	// generations (non-current, unsealed, not the declared parent). Inspect
	// reports what Reconcile would quarantine; Reconcile moves them without
	// granting them selection, rollback, or historical authority.
	Quarantined []QuarantineRecord
	// DiscardedStaging are .staging-* directories that never published,
	// plus orphaned durable-write temp files (seal.json.tmp-*) inside the
	// current generation — both crash residue that never carried state.
	DiscardedStaging []string
	// SealedPriors are retained committed prior generations, newest first.
	SealedPriors []string
	// RetainedUnsealedParent is set when the current generation's manifest
	// ParentID names a generation whose seal is missing. The parent was
	// committed once (the seal precedes every flip), so a missing seal is
	// damage, not an uncommitted attempt: reconciliation retains it and
	// pruning refuses to run until the operator restores or removes it.
	RetainedUnsealedParent string
}

// Moved describes, one line each, what a reconciliation quarantined or
// discarded: what an offline mint, which no unlock precedes, reports after
// it reconciles.
func (r ReconcileReport) Moved() []string {
	moved := make([]string, 0, len(r.Quarantined)+len(r.DiscardedStaging))
	for _, quarantined := range r.Quarantined {
		moved = append(moved, "quarantined uncommitted generation "+quarantined.GenerationID)
	}
	for _, residue := range r.DiscardedStaging {
		moved = append(moved, "discarded crash residue "+residue)
	}
	return moved
}

// InspectStoreRoot authenticates a fresh root read and classifies generation
// residue without changing it.
func InspectStoreRoot(paths storepaths.Paths, kr *crypto.Keyring) (ReconcileReport, error) {
	selected, err := AuthenticateStoreRootSelection(paths, kr)
	if err != nil {
		return ReconcileReport{}, fmt.Errorf("reconcile: %w", err)
	}
	return reconcileSelected(paths, selected.GenerationID(), kr, false)
}

// ReconcileStoreRoot authenticates the sole commit record before relocating or
// deleting any residue. The caller holds the mutation lock and an open keyring.
func ReconcileStoreRoot(paths storepaths.Paths, kr *crypto.Keyring) (ReconcileReport, error) {
	selected, err := AuthenticateStoreRootSelection(paths, kr)
	if err != nil {
		return ReconcileReport{}, fmt.Errorf("reconcile: %w", err)
	}
	return reconcileSelected(paths, selected.GenerationID(), kr, true)
}

func reconcileSelected(paths storepaths.Paths, current string, kr *crypto.Keyring, remove bool) (ReconcileReport, error) {
	report := ReconcileReport{}
	report.Current = current

	// Everything below deletes state, so the committed generation must be
	// proven valid first — reconciliation under a broken current would be
	// destroying the material recovery needs. The current manifest's
	// ParentID is derived here for the same reason: the parent was
	// committed once (its seal preceded the flip to current), so if its
	// seal is now missing that is damage, not an uncommitted attempt, and
	// it must survive reconciliation for the operator.
	if err := ValidateCurrent(paths.GenerationPaths(current)); err != nil {
		return report, fmt.Errorf("reconcile: current generation failed validation, nothing deleted: %w", err)
	}
	manifest, err := ReadManifest(paths.GenerationPaths(current))
	if err != nil {
		return report, fmt.Errorf("reconcile: %w", err)
	}
	retainedParent := manifest.ParentID

	if remove {
		// Re-confirm the commit record's directory durability. A commit that
		// ended with an uncertainty error may have left the root visible but its
		// directory fsync unproven; nothing else ever re-syncs it, so the
		// next unlock would resume signing on a flip a later power loss
		// could silently revert. Reconciliation is the designated healing
		// point: fsync the identity directory so the pointer read above is
		// durably the pointer.
		if err := fsutil.SyncDir(paths.ProductDir()); err != nil {
			return report, fmt.Errorf("reconcile: confirm store root durability: %w", err)
		}
	}

	if err := sweepWriteResidue(paths, current, remove, &report); err != nil {
		return report, err
	}

	generationsDir := paths.GenerationsDir()
	entries, err := os.ReadDir(generationsDir)
	if err != nil {
		return report, err
	}
	quarantineCount, quarantineBytes, err := quarantineUsage(paths)
	if err != nil {
		return report, fmt.Errorf("inspect generation quarantine: %w", err)
	}
	removedAny := false
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case strings.HasPrefix(name, storepaths.GenerationStagingPrefix):
			if remove {
				if err := os.RemoveAll(paths.GenerationsDir() + "/" + name); err != nil {
					return report, fmt.Errorf("discard staging %s: %w", name, err)
				}
				removedAny = true
			}
			report.DiscardedStaging = append(report.DiscardedStaging, name)
		case name == current:
			// The committed state; validated by the caller via
			// ValidateCurrent.
		default:
			if err := storepaths.ValidateGenerationID(name); err != nil {
				// Unknown entries are not ours to delete; fail closed.
				return report, fmt.Errorf("unexpected entry %q in generations directory", name)
			}
			gen := paths.GenerationPaths(name)
			sealed, err := HasSeal(gen)
			if err != nil {
				return report, err
			}
			if sealed || name == retainedParent {
				if sealed {
					report.SealedPriors = append(report.SealedPriors, name)
				} else if name == retainedParent {
					report.RetainedUnsealedParent = name
				}
				continue
			}
			// Non-current and unsealed is ambiguous: normally it is an
			// uncommitted attempt, but restoring an older authentic store root
			// can give the real newer state the same shape. Classify it only for
			// safe bounded relocation; quarantine never grants authority.
			candidate, err := classifyQuarantineCandidate(gen, kr)
			if err != nil {
				return report, fmt.Errorf(
					"generation %s cannot be safely quarantined and was preserved in place: %w",
					name,
					err,
				)
			}
			if err := checkQuarantineCapacity(quarantineCount, quarantineBytes, candidate); err != nil {
				return report, err
			}
			if remove {
				if err := quarantinePublication(paths, candidate); err != nil {
					return report, err
				}
			}
			report.Quarantined = append(report.Quarantined, candidate)
			quarantineCount++
			quarantineBytes += candidate.EncodedBytes
		}
	}
	if removedAny {
		if err := fsutil.SyncDir(generationsDir); err != nil {
			return report, err
		}
	}
	// Deterministic order only; ID sort is NOT lineage (same-second mints
	// tie-break on a random suffix, and a rollback makes the newest ID the
	// rolled-away child, not an ancestor). Retention decisions come from
	// manifest ParentID, never from this ordering.
	slices.Sort(report.SealedPriors)
	slices.Reverse(report.SealedPriors)
	return report, nil
}

// sweepWriteResidue garbage-collects orphaned durable-write temp files in the
// current generation (a crash mid-seal leaves seal.json.tmp-* at the
// generation root; the committing rename is atomic, so residue never
// carries state). Structural validation tolerates them; this is where
// they are removed, or only reported when remove is unset.
func sweepWriteResidue(paths storepaths.Paths, current string, remove bool, report *ReconcileReport) error {
	gen := paths.GenerationPaths(current)
	residue, err := WriteResidue(gen)
	if err != nil {
		return err
	}
	for _, relative := range residue {
		name := filepath.Base(relative)
		if remove {
			if err := fsutil.RemoveDurable(filepath.Join(gen.Dir(), filepath.FromSlash(relative))); err != nil {
				return fmt.Errorf("discard durable-write residue %s: %w", name, err)
			}
		}
		report.DiscardedStaging = append(report.DiscardedStaging, name)
	}
	return nil
}

// WriteResidue lists the orphaned durable-write temp files in gen, relative
// to its directory and slash-separated: what reconciliation discards from
// the current generation.
func WriteResidue(gen storepaths.GenPaths) ([]string, error) {
	var residue []string
	for _, namespace := range append([]string{""}, generationLeafNamespaces...) {
		entries, err := os.ReadDir(filepath.Join(gen.Dir(), namespace))
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			name := entry.Name()
			// Root residue is a crashed seal/manifest write; namespace
			// residue is a crashed durable single-file write inside the
			// mutable current generation. Neither ever carries state (the
			// committing rename is atomic), and unswept namespace residue
			// would be copied into every child generation and sealed there.
			isResidue := isDurableWriteResidue(name) ||
				(namespace != "" && hasDurableWriteTempSuffix(name))
			if entry.IsDir() || !isResidue {
				continue
			}
			residue = append(residue, path.Join(namespace, name))
		}
	}
	return residue, nil
}

// CollectGarbageStoreRoot prunes retained generations only after the sole
// store root and its selection have been authenticated under kr.
func CollectGarbageStoreRoot(paths storepaths.Paths, retainRollbackParent bool, kr *crypto.Keyring) ([]string, error) {
	report, err := ReconcileStoreRoot(paths, kr)
	if err != nil {
		return nil, err
	}
	return collectGarbageFromReport(paths, retainRollbackParent, kr, report)
}

func collectGarbageFromReport(paths storepaths.Paths, retainRollbackParent bool, kr *crypto.Keyring, report ReconcileReport) ([]string, error) {
	// Reconcile has already validated the current generation (structure and
	// manifest completeness) before its own deletions; nothing here runs
	// against an unvalidated current.
	if report.RetainedUnsealedParent != "" {
		return nil, fmt.Errorf("collect: rollback parent %s is missing its seal, refusing to prune; restore the parent's seal or remove the generation manually", report.RetainedUnsealedParent)
	}
	if len(report.SealedPriors) == 0 {
		// Nothing to delete. Succeed as a no-op without demanding the
		// manifest's ParentID still exist: after an --all-priors prune
		// (the rotation-quiescence workflow) that parent was deleted
		// deliberately, and an ordinary prune must stay idempotent.
		// When deletable priors DO exist while the declared parent is
		// missing, the fail-closed seal validation below still applies.
		return nil, nil
	}
	retainedParent := ""
	if retainRollbackParent {
		manifest, err := ReadManifest(paths.GenerationPaths(report.Current))
		if err != nil {
			return nil, fmt.Errorf("collect: read current generation manifest: %w", err)
		}
		if manifest.ParentID != "" {
			// The retained parent is being kept as the rollback target;
			// a parent that fails seal validation cannot serve that role,
			// and deleting the alternatives would destroy the only other
			// recovery material. Abort the prune before removing anything.
			parent := paths.GenerationPaths(manifest.ParentID)
			var validateErr error
			if anchor, anchored := kr.HistoricalGenerationAnchor(manifest.ParentID); anchored {
				validateErr = ValidateAnchoredSealed(parent, anchor, kr)
			} else {
				validateErr = ValidateSealed(parent, kr)
			}
			if validateErr != nil {
				return nil, fmt.Errorf("collect: rollback parent %s failed seal validation, refusing to prune: %w", manifest.ParentID, validateErr)
			}
			retainedParent = manifest.ParentID
		}
	}
	var removed []string
	for _, name := range report.SealedPriors {
		if name == retainedParent {
			continue
		}
		// Deletion is not atomic: a crash mid-RemoveAll would leave a
		// half-deleted generation that later classification could only
		// treat as damage (wedging every subsequent prune fail-closed).
		// Rename to a staging tombstone first — atomic, and staging
		// residue is unconditionally garbage to reconciliation — so a
		// crashed prune retries as a no-op instead of wedging.
		tombstone := filepath.Join(paths.GenerationsDir(), storepaths.GenerationStagingPrefix+"prune-"+name)
		if err := os.Rename(paths.GenerationPaths(name).Dir(), tombstone); err != nil {
			return removed, fmt.Errorf("collect generation %s: %w", name, err)
		}
		if err := os.RemoveAll(tombstone); err != nil {
			return removed, fmt.Errorf("collect generation %s: %w", name, err)
		}
		removed = append(removed, name)
	}
	if len(removed) > 0 {
		if err := fsutil.SyncDir(paths.GenerationsDir()); err != nil {
			return removed, err
		}
	}
	return removed, nil
}
