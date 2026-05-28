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
// already registered in the process-global provider registry.
func CompareForReload(rec Record, fileFingerprint, registryFingerprint string) ReloadOutcome {
	if rec.Source == SourceYAMLGeneric || rec.Source == SourceYAMLComposed {
		if fileFingerprint == "" {
			return OutcomeOrphanedRecord
		}
		if rec.Fingerprint != "" && fileFingerprint != rec.Fingerprint {
			return OutcomeExternalEdit
		}
	}
	if rec.Fingerprint == "" {
		return OutcomeRegister
	}
	if registryFingerprint == "" {
		return OutcomeRegister
	}
	if registryFingerprint == rec.Fingerprint {
		return OutcomeIdempotent
	}
	return OutcomeConflict
}
