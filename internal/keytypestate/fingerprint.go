// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypestate

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
// already registered in the process-global provider registry. A pinned
// fingerprint agrees only when it is byte-identical to the other: one with
// another version prefix, or no prefix, is an external edit or a conflict like
// any other difference. A record that pinned nothing is compared with nothing.
func CompareForReload(rec Record, fileFingerprint, registryFingerprint string) ReloadOutcome {
	if rec.Source == SourceYAMLGeneric || rec.Source == SourceYAMLComposed {
		if fileFingerprint == "" {
			return OutcomeOrphanedRecord
		}
		if rec.Fingerprint != "" && rec.Fingerprint != fileFingerprint {
			return OutcomeExternalEdit
		}
	}
	if rec.Fingerprint == "" || registryFingerprint == "" {
		return OutcomeRegister
	}
	if rec.Fingerprint == registryFingerprint {
		return OutcomeIdempotent
	}
	return OutcomeConflict
}
