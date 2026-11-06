// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypestate

import (
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// RequiresCurrentApproval reports whether keyType needs its current fingerprint
// approved, rather than merely being enabled, before creating an account.
func RequiresCurrentApproval(keyType string) bool {
	gated, ok := lsigprovider.Get(keyType).(lsigprovider.ApprovalGated)
	return ok && gated.GenerationRequiresCurrentApproval()
}

// NeedsApproval reports whether a key type that requires current approval lacks
// it. This is stricter than reload comparison on purpose: a missing, malformed,
// or incomparable fingerprint is benign when deciding whether a record conflicts,
// but it does not show that anyone approved this definition. It reads no state
// for any other key type, so their behavior cannot change.
//
// A corrupt record returns an error, so it surfaces as a storage problem rather
// than as a prompt to approve over it.
func NeedsApproval(paths storepaths.Paths, keyType string) (bool, error) {
	if !RequiresCurrentApproval(keyType) {
		return false, nil
	}
	current, ok := lsigprovider.CompatibilityFingerprintOf(lsigprovider.Get(keyType))
	if !ok {
		return true, nil
	}
	rec, found, err := Get(paths, keyType)
	if err != nil {
		return false, err
	}
	if !found || rec.State != StateEnabled {
		return true, nil
	}
	match, comparable := lsigprovider.FingerprintsMatch(rec.Fingerprint, current)
	return !match || !comparable, nil
}

type ReloadOutcome int

const (
	OutcomeRegister ReloadOutcome = iota
	OutcomeIdempotent
	OutcomeConflict
	OutcomeExternalEdit
	OutcomeOrphanedRecord
)

// CompareForReload compares the fingerprint pinned in an enabled record with
// the fingerprint computed from the current template file and the fingerprint
// already registered in the process-global provider registry.
// All fingerprint comparisons are version-aware: only a same-version,
// different-hash pair signals a real behavior difference (external edit /
// conflict). A cross-version or unparseable pair is "not comparable" and is
// treated benignly (no external edit; fall through to registration / no
// conflict), so a future fingerprint-formula bump cannot false-flag existing
// records.
func CompareForReload(rec Record, fileFingerprint, registryFingerprint string) ReloadOutcome {
	if rec.Source == SourceYAMLGeneric || rec.Source == SourceYAMLComposed {
		if fileFingerprint == "" {
			return OutcomeOrphanedRecord
		}
		if rec.Fingerprint != "" {
			if match, comparable := lsigprovider.FingerprintsMatch(rec.Fingerprint, fileFingerprint); comparable && !match {
				return OutcomeExternalEdit
			}
		}
	}
	if rec.Fingerprint == "" {
		return OutcomeRegister
	}
	if registryFingerprint == "" {
		return OutcomeRegister
	}
	match, comparable := lsigprovider.FingerprintsMatch(rec.Fingerprint, registryFingerprint)
	if !comparable {
		return OutcomeRegister
	}
	if match {
		return OutcomeIdempotent
	}
	return OutcomeConflict
}
