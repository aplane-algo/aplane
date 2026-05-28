// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templates

import (
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatepolicy"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

type PrepareFunc func(keyType string, data []byte) (templatepolicy.PreparedTemplateRegistration, error)

type TemplateRegistrar struct {
	Name         string
	Source       keytypestate.Source
	TemplateType templatestore.TemplateType
	Prepare      PrepareFunc
}

type RegistrationReport struct {
	GenericErr  error
	ComposedErr error

	GenericActivatedKeyTypes     []string
	ComposedActivatedKeyTypes    []string
	GenericIdempotentKeyTypes    []string
	ComposedIdempotentKeyTypes   []string
	GenericDisabledKeyTypes      []string
	ComposedDisabledKeyTypes     []string
	GenericConflictingKeyTypes   []string
	ComposedConflictingKeyTypes  []string
	GenericInvalidKeyTypes       []string
	ComposedInvalidKeyTypes      []string
	InvalidStateRecordKeyTypes   []string
	CompiledInvalidKeyTypes      []string
	GenericExternalEditKeyTypes  []string
	ComposedExternalEditKeyTypes []string
	GenericOrphanedKeyTypes      []string
	ComposedOrphanedKeyTypes     []string
	CompiledIdempotentKeyTypes   []string
	CompiledConflictingKeyTypes  []string
}

func (r RegistrationReport) Warnings() []string {
	var warnings []string
	if r.GenericErr != nil {
		warnings = append(warnings, fmt.Sprintf("failed to load generic templates: %v", r.GenericErr))
	}
	if r.ComposedErr != nil {
		warnings = append(warnings, fmt.Sprintf("failed to load composed templates: %v", r.ComposedErr))
	}
	if len(r.GenericConflictingKeyTypes) > 0 {
		warnings = append(warnings, fmt.Sprintf("conflicting generic templates ignored on reload: %v (restart apsigner to redefine)", r.GenericConflictingKeyTypes))
	}
	if len(r.ComposedConflictingKeyTypes) > 0 {
		warnings = append(warnings, fmt.Sprintf("conflicting composed templates ignored on reload: %v (restart apsigner to redefine)", r.ComposedConflictingKeyTypes))
	}
	if len(r.GenericInvalidKeyTypes) > 0 {
		warnings = append(warnings, fmt.Sprintf("invalid generic templates ignored on reload: %v", r.GenericInvalidKeyTypes))
	}
	if len(r.ComposedInvalidKeyTypes) > 0 {
		warnings = append(warnings, fmt.Sprintf("invalid composed templates ignored on reload: %v", r.ComposedInvalidKeyTypes))
	}
	if len(r.InvalidStateRecordKeyTypes) > 0 {
		warnings = append(warnings, fmt.Sprintf("invalid key type state records ignored on reload: %v", r.InvalidStateRecordKeyTypes))
	}
	if len(r.CompiledInvalidKeyTypes) > 0 {
		warnings = append(warnings, fmt.Sprintf("invalid compiled key type records ignored on reload: %v", r.CompiledInvalidKeyTypes))
	}
	if len(r.CompiledConflictingKeyTypes) > 0 {
		warnings = append(warnings, fmt.Sprintf("conflicting compiled key type records ignored on reload: %v (restart apsigner to redefine)", r.CompiledConflictingKeyTypes))
	}
	if len(r.GenericExternalEditKeyTypes) > 0 {
		warnings = append(warnings, fmt.Sprintf("externally edited generic templates ignored on reload: %v (reinstall via `apstore template import`)", r.GenericExternalEditKeyTypes))
	}
	if len(r.ComposedExternalEditKeyTypes) > 0 {
		warnings = append(warnings, fmt.Sprintf("externally edited composed templates ignored on reload: %v (reinstall via `apstore template import`)", r.ComposedExternalEditKeyTypes))
	}
	if len(r.GenericOrphanedKeyTypes) > 0 {
		warnings = append(warnings, fmt.Sprintf("generic template state records without template files ignored on reload: %v (reinstall via `apstore template import`)", r.GenericOrphanedKeyTypes))
	}
	if len(r.ComposedOrphanedKeyTypes) > 0 {
		warnings = append(warnings, fmt.Sprintf("composed template state records without template files ignored on reload: %v (reinstall via `apstore template import`)", r.ComposedOrphanedKeyTypes))
	}
	return warnings
}

func (r RegistrationReport) Notices() []string {
	var notices []string
	if len(r.GenericActivatedKeyTypes) > 0 {
		notices = append(notices, fmt.Sprintf("new generic template key types activated on reload: %v", r.GenericActivatedKeyTypes))
	}
	if len(r.ComposedActivatedKeyTypes) > 0 {
		notices = append(notices, fmt.Sprintf("new composed template key types activated on reload: %v", r.ComposedActivatedKeyTypes))
	}
	return notices
}

// Manager owns keystore template registration ordering for signer reloads.
type Manager struct {
	Paths      storepaths.Paths
	Registrars []TemplateRegistrar
}

func NewManager(paths storepaths.Paths) *Manager {
	return &Manager{
		Paths:      paths,
		Registrars: DefaultTemplateRegistrars(),
	}
}

func DefaultTemplateRegistrars() []TemplateRegistrar {
	return []TemplateRegistrar{
		{
			Name:         "generic",
			Source:       keytypestate.SourceYAMLGeneric,
			TemplateType: templatestore.TemplateTypeGeneric,
			Prepare:      generictemplate.PrepareKeystoreTemplateRegistration,
		},
		{
			Name:         "composed",
			Source:       keytypestate.SourceYAMLComposed,
			TemplateType: templatestore.TemplateTypeComposed,
			Prepare:      composeddsa.PrepareKeystoreTemplateRegistration,
		},
	}
}

// RegisterKeystoreTemplates registers all keystore-backed template families.
// The ordering is compatibility-sensitive: generic and composed templates must
// be registered before key scanning occurs so provider metadata is available.
// Recoverable reload problems are surfaced through the returned report; the
// error return is reserved for manager misconfiguration and unrecoverable work
// that should stop the caller's reload flow.
func (m *Manager) RegisterKeystoreTemplates(identityID string, masterKey []byte) (RegistrationReport, error) {
	registrars, err := m.templateRegistrars()
	if err != nil {
		return RegistrationReport{}, err
	}

	report := RegistrationReport{}
	records, err := keytypestate.List(m.Paths, identityID)
	if err != nil {
		return report, fmt.Errorf("failed to load keystore templates: %w", err)
	}

	registrarsBySource := make(map[keytypestate.Source]TemplateRegistrar, len(registrars))
	for _, registrar := range registrars {
		registrarsBySource[registrar.Source] = registrar
	}

	// Reload is state-record driven: stray encrypted .template files without a
	// matching key type state record are intentionally invisible.
	for _, rec := range records {
		registrar, ok := registrarsBySource[rec.Source]
		if !ok {
			continue
		}
		outcome := registerTemplateRecord(m.Paths, identityID, masterKey, rec, registrar)
		appendOutcome(&report, registrar.Source, outcome)
	}

	if invalid, listErr := keytypestate.ListInvalid(m.Paths, identityID); listErr == nil {
		report.InvalidStateRecordKeyTypes = append(report.InvalidStateRecordKeyTypes, invalid...)
	}

	compiledOutcome := validateCompiledProviderRecords(records)
	report.CompiledIdempotentKeyTypes = append(report.CompiledIdempotentKeyTypes, compiledOutcome.IdempotentKeyTypes...)
	report.CompiledConflictingKeyTypes = append(report.CompiledConflictingKeyTypes, compiledOutcome.ConflictingKeyTypes...)
	report.CompiledInvalidKeyTypes = append(report.CompiledInvalidKeyTypes, compiledOutcome.InvalidKeyTypes...)

	return report, nil
}

func (m *Manager) templateRegistrars() ([]TemplateRegistrar, error) {
	registrars := m.Registrars
	if len(registrars) == 0 {
		registrars = DefaultTemplateRegistrars()
	}
	seen := make(map[keytypestate.Source]struct{}, len(registrars))
	for _, registrar := range registrars {
		if registrar.Prepare == nil {
			return nil, fmt.Errorf("%s template registrar not configured", registrar.Name)
		}
		if _, ok := seen[registrar.Source]; ok {
			return nil, fmt.Errorf("duplicate template registrar for source %q", registrar.Source)
		}
		seen[registrar.Source] = struct{}{}
	}
	return registrars, nil
}

func registerTemplateRecord(paths storepaths.Paths, identityID string, masterKey []byte, rec keytypestate.Record, registrar TemplateRegistrar) templatepolicy.RegistrationOutcome {
	var outcome templatepolicy.RegistrationOutcome
	path := templatestore.GetTemplateFilePathForPaths(paths, identityID, rec.KeyType, registrar.TemplateType)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			if rec.State == keytypestate.StateEnabled {
				outcome.OrphanedKeyTypes = append(outcome.OrphanedKeyTypes, rec.KeyType)
			}
			return outcome
		}
		outcome.InvalidKeyTypes = append(outcome.InvalidKeyTypes, rec.KeyType)
		return outcome
	}
	if rec.State == keytypestate.StateDisabled {
		outcome.DisabledKeyTypes = append(outcome.DisabledKeyTypes, rec.KeyType)
		return outcome
	}

	data, err := templatestore.LoadTemplateFromPath(path, masterKey)
	if err != nil {
		outcome.InvalidKeyTypes = append(outcome.InvalidKeyTypes, rec.KeyType)
		return outcome
	}
	prepared, err := registrar.Prepare(rec.KeyType, data)
	if err != nil {
		outcome.InvalidKeyTypes = append(outcome.InvalidKeyTypes, rec.KeyType)
		return outcome
	}

	incomingFingerprint := prepared.Fingerprint
	registryFingerprint := ""
	if existing := lsigprovider.Get(rec.KeyType); existing != nil {
		var ok bool
		registryFingerprint, ok = lsigprovider.CompatibilityFingerprintOf(existing)
		if !ok {
			outcome.ConflictingKeyTypes = append(outcome.ConflictingKeyTypes, rec.KeyType)
			return outcome
		}
	}
	switch keytypestate.CompareForReload(rec, incomingFingerprint, registryFingerprint) {
	case keytypestate.OutcomeExternalEdit:
		outcome.ExternalEditKeyTypes = append(outcome.ExternalEditKeyTypes, rec.KeyType)
		return outcome
	case keytypestate.OutcomeOrphanedRecord:
		outcome.OrphanedKeyTypes = append(outcome.OrphanedKeyTypes, rec.KeyType)
		return outcome
	case keytypestate.OutcomeConflict:
		outcome.ConflictingKeyTypes = append(outcome.ConflictingKeyTypes, rec.KeyType)
		return outcome
	case keytypestate.OutcomeIdempotent:
		outcome.IdempotentKeyTypes = append(outcome.IdempotentKeyTypes, rec.KeyType)
		return outcome
	}

	if existing := lsigprovider.Get(rec.KeyType); existing != nil {
		if existingFingerprint, ok := lsigprovider.CompatibilityFingerprintOf(existing); ok && existingFingerprint == incomingFingerprint {
			outcome.IdempotentKeyTypes = append(outcome.IdempotentKeyTypes, rec.KeyType)
		} else {
			outcome.ConflictingKeyTypes = append(outcome.ConflictingKeyTypes, rec.KeyType)
		}
		return outcome
	}

	if !prepared.Register() {
		outcome.ConflictingKeyTypes = append(outcome.ConflictingKeyTypes, rec.KeyType)
		return outcome
	}
	outcome.ActivatedKeyTypes = append(outcome.ActivatedKeyTypes, rec.KeyType)
	return outcome
}

func validateCompiledProviderRecords(records []keytypestate.Record) templatepolicy.RegistrationOutcome {
	var outcome templatepolicy.RegistrationOutcome
	for _, rec := range records {
		if rec.Source != keytypestate.SourceCompiled {
			continue
		}
		if rec.State == keytypestate.StateDisabled {
			outcome.DisabledKeyTypes = append(outcome.DisabledKeyTypes, rec.KeyType)
			continue
		}
		provider := lsigprovider.Get(rec.KeyType)
		if provider == nil {
			outcome.InvalidKeyTypes = append(outcome.InvalidKeyTypes, rec.KeyType)
			continue
		}
		registryFingerprint, ok := lsigprovider.CompatibilityFingerprintOf(provider)
		if !ok {
			registryFingerprint = ""
		}
		if rec.Fingerprint != "" && registryFingerprint != rec.Fingerprint {
			outcome.ConflictingKeyTypes = append(outcome.ConflictingKeyTypes, rec.KeyType)
			continue
		}
		outcome.IdempotentKeyTypes = append(outcome.IdempotentKeyTypes, rec.KeyType)
	}
	return outcome
}

func appendOutcome(report *RegistrationReport, source keytypestate.Source, outcome templatepolicy.RegistrationOutcome) {
	switch source {
	case keytypestate.SourceYAMLComposed:
		report.ComposedActivatedKeyTypes = append(report.ComposedActivatedKeyTypes, outcome.ActivatedKeyTypes...)
		report.ComposedIdempotentKeyTypes = append(report.ComposedIdempotentKeyTypes, outcome.IdempotentKeyTypes...)
		report.ComposedDisabledKeyTypes = append(report.ComposedDisabledKeyTypes, outcome.DisabledKeyTypes...)
		report.ComposedConflictingKeyTypes = append(report.ComposedConflictingKeyTypes, outcome.ConflictingKeyTypes...)
		report.ComposedInvalidKeyTypes = append(report.ComposedInvalidKeyTypes, outcome.InvalidKeyTypes...)
		report.ComposedExternalEditKeyTypes = append(report.ComposedExternalEditKeyTypes, outcome.ExternalEditKeyTypes...)
		report.ComposedOrphanedKeyTypes = append(report.ComposedOrphanedKeyTypes, outcome.OrphanedKeyTypes...)
	case keytypestate.SourceYAMLGeneric:
		report.GenericActivatedKeyTypes = append(report.GenericActivatedKeyTypes, outcome.ActivatedKeyTypes...)
		report.GenericIdempotentKeyTypes = append(report.GenericIdempotentKeyTypes, outcome.IdempotentKeyTypes...)
		report.GenericDisabledKeyTypes = append(report.GenericDisabledKeyTypes, outcome.DisabledKeyTypes...)
		report.GenericConflictingKeyTypes = append(report.GenericConflictingKeyTypes, outcome.ConflictingKeyTypes...)
		report.GenericInvalidKeyTypes = append(report.GenericInvalidKeyTypes, outcome.InvalidKeyTypes...)
		report.GenericExternalEditKeyTypes = append(report.GenericExternalEditKeyTypes, outcome.ExternalEditKeyTypes...)
		report.GenericOrphanedKeyTypes = append(report.GenericOrphanedKeyTypes, outcome.OrphanedKeyTypes...)
	}
}
