// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"fmt"
	"os"
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
	// generations (non-current, unsealed, unreferenced). Inspect reports what
	// Reconcile would quarantine; Reconcile moves them without granting them
	// selection, rollback, or historical authority.
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

// Inspect classifies the generations directory without deleting anything:
// the same validation and classification Reconcile applies, with
// DiscardedStaging and Quarantined reporting what reconciliation WOULD remove
// or relocate. Read-only callers (apadmin generations list) use this;
// everything else goes through Reconcile.
func Inspect(paths storepaths.Paths, referenced map[string]bool) (ReconcileReport, error) {
	current, err := ReadCurrent(paths)
	if err != nil {
		return ReconcileReport{}, fmt.Errorf("reconcile: %w", err)
	}
	return reconcileSelected(paths, current, referenced, false)
}

// InspectStoreRoot authenticates a fresh root read and classifies generation
// residue without changing it.
func InspectStoreRoot(paths storepaths.Paths, kr *crypto.Keyring, referenced map[string]bool) (ReconcileReport, error) {
	current, err := selectedGenerationFromStoreRoot(paths, kr)
	if err != nil {
		return ReconcileReport{}, fmt.Errorf("reconcile: %w", err)
	}
	return reconcileSelected(paths, current, referenced, false)
}

// Reconcile enforces CURRENT as the sole commit record. Run at
// startup/unlock under the store and store mutation locks, before any
// new operation:
//
//   - CURRENT names a valid generation → it is authoritative; every
//     published-but-uncommitted attempt (non-current, unsealed, not in
//     referenced) is moved to bounded non-authoritative quarantine, never
//     resumed. Staging directories are unconditionally garbage.
//   - CURRENT missing or invalid → error; the caller enters recovery mode
//     and nothing is deleted.
//
// referenced names generation IDs that incomplete-operation or audit
// recovery metadata still points at; those survive regardless of seal
// state. Eligibility is reachability-based, not parentage-based: a stale
// attempt whose parent has since been superseded is still collected.
func Reconcile(paths storepaths.Paths, referenced map[string]bool) (ReconcileReport, error) {
	current, err := ReadCurrent(paths)
	if err != nil {
		return ReconcileReport{}, fmt.Errorf("reconcile: %w", err)
	}
	return reconcileSelected(paths, current, referenced, true)
}

// ReconcileStoreRoot authenticates the sole commit record before relocating or
// deleting any residue. The caller holds the mutation lock and an open keyring.
func ReconcileStoreRoot(paths storepaths.Paths, kr *crypto.Keyring, referenced map[string]bool) (ReconcileReport, error) {
	current, err := selectedGenerationFromStoreRoot(paths, kr)
	if err != nil {
		return ReconcileReport{}, fmt.Errorf("reconcile: %w", err)
	}
	return reconcileSelected(paths, current, referenced, true)
}

func selectedGenerationFromStoreRoot(paths storepaths.Paths, kr *crypto.Keyring) (string, error) {
	exact, err := crypto.ReadStoreRootExact(paths.KeystoreMetadataDir())
	if err != nil {
		return "", err
	}
	selection, err := crypto.AuthenticateStoreRoot(exact, kr)
	if err != nil {
		return "", fmt.Errorf("authenticate store root: %w", err)
	}
	return selection.CurrentGenerationID, nil
}

func reconcileSelected(paths storepaths.Paths, current string, referenced map[string]bool, remove bool) (ReconcileReport, error) {
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

	// Garbage-collect orphaned durable-write temp files in the current
	// generation (a crash mid-seal leaves seal.json.tmp-* at the
	// generation root; the committing rename is atomic, so residue never
	// carries state). Structural validation tolerates them; this is where
	// they are removed.
	currentDir := paths.GenerationPaths(current).Dir()
	residueDirs := []string{currentDir}
	for _, namespace := range generationLeafNamespaces {
		residueDirs = append(residueDirs, filepath.Join(currentDir, namespace))
	}
	for _, dir := range residueDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return report, err
		}
		for _, entry := range entries {
			name := entry.Name()
			// Root residue is a crashed seal/manifest write; namespace
			// residue is a crashed durable single-file write inside the
			// mutable current generation. Neither ever carries state (the
			// committing rename is atomic), and unswept namespace residue
			// would be copied into every child generation and sealed there.
			isResidue := isDurableWriteResidue(name) ||
				(dir != currentDir && hasDurableWriteTempSuffix(name))
			if entry.IsDir() || !isResidue {
				continue
			}
			if remove {
				if err := fsutil.RemoveDurable(filepath.Join(dir, name)); err != nil {
					return report, fmt.Errorf("discard durable-write residue %s: %w", name, err)
				}
			}
			report.DiscardedStaging = append(report.DiscardedStaging, name)
		}
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
			if sealed || referenced[name] || name == retainedParent {
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
			candidate, err := classifyQuarantineCandidate(gen)
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

// CollectGarbage removes sealed prior generations beyond the retention set:
// the current generation, its manifest's ParentID (the true rollback target,
// unless retainRollbackParent is false — the pre-rotation quiescence prune),
// and anything in referenced. Retention is manifest-driven, never
// ID-ordering-driven: same-second mints tie-break on a random suffix, and
// after a rollback the "newest" prior is the rolled-away child rather than
// an ancestor. Never call during activation, rotation, reload, or
// migration; the caller holds the mutation locks. Reconcile runs first
// (staging is discarded, ambiguous unsealed publications are quarantined,
// and an invalid CURRENT aborts with nothing changed).
func CollectGarbage(paths storepaths.Paths, referenced map[string]bool, retainRollbackParent bool, kr *crypto.Keyring) ([]string, error) {
	report, err := Reconcile(paths, referenced)
	if err != nil {
		return nil, err
	}
	return collectGarbageFromReport(paths, referenced, retainRollbackParent, kr, report)
}

// CollectGarbageStoreRoot prunes retained generations only after the sole
// store root and its selection have been authenticated under kr.
func CollectGarbageStoreRoot(paths storepaths.Paths, referenced map[string]bool, retainRollbackParent bool, kr *crypto.Keyring) ([]string, error) {
	report, err := ReconcileStoreRoot(paths, kr, referenced)
	if err != nil {
		return nil, err
	}
	return collectGarbageFromReport(paths, referenced, retainRollbackParent, kr, report)
}

func collectGarbageFromReport(paths storepaths.Paths, referenced map[string]bool, retainRollbackParent bool, kr *crypto.Keyring, report ReconcileReport) ([]string, error) {
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
	retain := make(map[string]bool, len(referenced)+1)
	for name, keep := range referenced {
		if keep {
			retain[name] = true
		}
	}
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
			retain[manifest.ParentID] = true
		}
	}
	var removed []string
	for _, name := range report.SealedPriors {
		if retain[name] {
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
