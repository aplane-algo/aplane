// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// ReconcileReport records what startup reconciliation found and removed.
type ReconcileReport struct {
	Current string
	// DiscardedAttempts are published-but-uncommitted generations that were
	// deleted (non-current, unsealed, unreferenced). Each is an activation
	// or migration that never committed; the operator reviews again.
	DiscardedAttempts []string
	// DiscardedStaging are .staging-* directories that never published.
	DiscardedStaging []string
	// SealedPriors are retained committed prior generations, newest first.
	SealedPriors []string
}

// Reconcile enforces CURRENT as the sole commit record. Run at
// startup/unlock under the store and identity mutation locks, before any
// new operation:
//
//   - CURRENT names a valid generation → it is authoritative; every
//     published-but-uncommitted attempt (non-current, unsealed, not in
//     referenced) is discarded, never resumed. Staging directories are
//     unconditionally garbage.
//   - CURRENT missing or invalid → error; the caller enters recovery mode
//     and nothing is deleted.
//
// referenced names generation IDs that incomplete-operation or audit
// recovery metadata still points at; those survive regardless of seal
// state. Eligibility is reachability-based, not parentage-based: a stale
// attempt whose parent has since been superseded is still collected.
func Reconcile(paths storepaths.Paths, identityID string, referenced map[string]bool) (ReconcileReport, error) {
	report := ReconcileReport{}
	current, err := ReadCurrent(paths, identityID)
	if err != nil {
		return report, fmt.Errorf("reconcile: %w", err)
	}
	report.Current = current

	generationsDir := paths.GenerationsDir(identityID)
	entries, err := os.ReadDir(generationsDir)
	if err != nil {
		return report, err
	}
	removedAny := false
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case strings.HasPrefix(name, storepaths.GenerationStagingPrefix):
			if err := os.RemoveAll(paths.GenerationsDir(identityID) + "/" + name); err != nil {
				return report, fmt.Errorf("discard staging %s: %w", name, err)
			}
			report.DiscardedStaging = append(report.DiscardedStaging, name)
			removedAny = true
		case name == current:
			// The committed state; validated by the caller via
			// ValidateCurrent.
		default:
			if err := storepaths.ValidateGenerationID(name); err != nil {
				// Unknown entries are not ours to delete; fail closed.
				return report, fmt.Errorf("unexpected entry %q in generations directory", name)
			}
			gen := paths.GenerationPaths(identityID, name)
			sealed, err := HasSeal(gen)
			if err != nil {
				return report, err
			}
			if sealed || referenced[name] {
				if sealed {
					report.SealedPriors = append(report.SealedPriors, name)
				}
				continue
			}
			// Non-current and unsealed: by construction an uncommitted
			// attempt (the seal precedes every flip). Discard.
			if err := os.RemoveAll(gen.Dir()); err != nil {
				return report, fmt.Errorf("discard uncommitted generation %s: %w", name, err)
			}
			report.DiscardedAttempts = append(report.DiscardedAttempts, name)
			removedAny = true
		}
	}
	if removedAny {
		if err := fsutil.SyncDir(generationsDir); err != nil {
			return report, err
		}
	}
	// Newest first: generation IDs sort by mint time.
	slices.Sort(report.SealedPriors)
	slices.Reverse(report.SealedPriors)
	return report, nil
}

// CollectGarbage removes sealed prior generations beyond the retention set:
// the current generation, the most recent sealed prior (the rollback target,
// unless retainNewestPrior is false — the pre-rotation quiescence prune),
// and anything in referenced. Never call during activation, rotation,
// reload, or migration; the caller holds the mutation locks. Reconcile runs
// first (staging and unsealed attempts are discarded, an invalid CURRENT
// aborts with nothing deleted).
func CollectGarbage(paths storepaths.Paths, identityID string, referenced map[string]bool, retainNewestPrior bool) ([]string, error) {
	report, err := Reconcile(paths, identityID, referenced)
	if err != nil {
		return nil, err
	}
	var removed []string
	for i, name := range report.SealedPriors {
		if (retainNewestPrior && i == 0) || referenced[name] {
			// Retain the newest sealed prior as the rollback target, and
			// everything still referenced.
			continue
		}
		if err := os.RemoveAll(paths.GenerationPaths(identityID, name).Dir()); err != nil {
			return removed, fmt.Errorf("collect generation %s: %w", name, err)
		}
		removed = append(removed, name)
	}
	if len(removed) > 0 {
		if err := fsutil.SyncDir(paths.GenerationsDir(identityID)); err != nil {
			return removed, err
		}
	}
	return removed, nil
}
