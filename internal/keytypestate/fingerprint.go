// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypestate

import "github.com/aplane-algo/aplane/internal/lsigprovider"

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
