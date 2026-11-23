// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templatepolicy

import "github.com/aplane-algo/aplane/internal/lsigprovider"

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
// validating one decrypted YAML template: the provider it registers, which
// keeps the provider contract (lsigprovider.CheckContract). Callers own
// lifecycle policy and register it only after state-record and registry
// compatibility checks pass.
type PreparedTemplateRegistration struct {
	Fingerprint string
	Provider    lsigprovider.LSigProvider
}
