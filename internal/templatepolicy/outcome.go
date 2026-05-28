// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templatepolicy

// RegistrationOutcome reports what happened while loading keystore-backed
// templates for a single family during reload/unlock.
type RegistrationOutcome struct {
	ActivatedKeyTypes    []string
	IdempotentKeyTypes   []string
	DisabledKeyTypes     []string
	ConflictingKeyTypes  []string
	InvalidKeyTypes      []string
	ExternalEditKeyTypes []string
	OrphanedKeyTypes     []string
}

// PreparedTemplateRegistration is the type-specific result of parsing and
// validating one decrypted YAML template. Callers own lifecycle policy and call
// Register only after state-record and registry compatibility checks pass.
type PreparedTemplateRegistration struct {
	Fingerprint string
	Register    func() bool
}
