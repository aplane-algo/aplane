// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templates

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/genstore"
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

// ContentDefectKeyTypes lists key types whose durable store content is
// malformed, unreadable, missing, or externally edited: invalid templates,
// invalid state records, orphaned records (state without a template file),
// and fingerprint mismatches. Registration-semantics categories (conflicts
// with process-global providers, idempotent re-registration, disabled
// records) are deliberately excluded — they are not store corruption. On a
// generation-based store any entry here fails the selected generation's
// validation (docs/ARCH_GENERATIONS.md §6).
func (r RegistrationReport) ContentDefectKeyTypes() []string {
	var defects []string
	for _, bucket := range [][]string{
		r.GenericInvalidKeyTypes,
		r.ComposedInvalidKeyTypes,
		r.InvalidStateRecordKeyTypes,
		r.CompiledInvalidKeyTypes,
		r.GenericOrphanedKeyTypes,
		r.ComposedOrphanedKeyTypes,
		r.GenericExternalEditKeyTypes,
		r.ComposedExternalEditKeyTypes,
		r.NamespaceDefects,
	} {
		defects = append(defects, bucket...)
	}
	return defects
}

type RegistrationReport struct {
	GenericErr  error
	ComposedErr error

	// NamespaceDefects are content problems found by sweeping the keytypes
	// namespace directly: unexpected entries, template files without a
	// state record, and templates (including disabled ones) that fail to
	// decrypt. Registration is record-driven and would never touch these.
	NamespaceDefects []string

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
	for _, defect := range r.NamespaceDefects {
		warnings = append(warnings, fmt.Sprintf("keytypes namespace defect: %s", defect))
	}
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
	// Resolve the active layout once for the whole registration pass; on a
	// generational store this binds every record and template read to the
	// generation CURRENT names right now.
	active, err := genstore.ResolveActive(m.Paths, identityID)
	if err != nil {
		return report, fmt.Errorf("failed to resolve active key store layout: %w", err)
	}
	records, err := keytypestate.ListActive(active)
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
		outcome := registerTemplateRecord(active, identityID, masterKey, rec, registrar)
		appendOutcome(&report, registrar.Source, outcome)
	}

	if invalid, listErr := keytypestate.ListInvalidActive(active); listErr == nil {
		report.InvalidStateRecordKeyTypes = append(report.InvalidStateRecordKeyTypes, invalid...)
	}
	// The namespace sweep is a generational-store integrity check backing
	// the fail-closed reload gate; legacy flat stores keep their historical
	// tolerance of stray files.
	if generational, genErr := genstore.IsGenerational(m.Paths, identityID); genErr != nil {
		return report, fmt.Errorf("failed to inspect store layout: %w", genErr)
	} else if generational {
		report.NamespaceDefects = sweepKeyTypeNamespace(active, masterKey, records)
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

// sweepKeyTypeNamespace validates the keytypes namespace of a generational
// store directly, catching what record-driven registration cannot: unexpected
// entries, template files without any state record, and disabled templates
// registration never decrypts. Enabled templates and malformed records are
// already covered by registration and ListInvalidActive; the sweep does not
// re-report them. Defects feed the fail-closed reload gate
// (docs/ARCH_GENERATIONS.md §6).
func sweepKeyTypeNamespace(active storepaths.ActivePaths, masterKey []byte, records []keytypestate.Record) []string {
	dir := active.KeyTypeRecordsDir()
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return []string{fmt.Sprintf("read keytypes namespace: %v", err)}
	}
	recordStates := make(map[string]keytypestate.State, len(records))
	for _, rec := range records {
		recordStates[rec.KeyType] = rec.State
	}
	recordFileExists := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			recordFileExists[strings.TrimSuffix(entry.Name(), ".json")] = true
		}
	}
	var defects []string
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case entry.IsDir():
			defects = append(defects, fmt.Sprintf("unexpected directory %q", name))
		case strings.HasSuffix(name, ".json"):
			// Record content validity is covered by ListInvalidActive.
		case strings.HasSuffix(name, ".template"):
			keyType := strings.TrimSuffix(name, ".template")
			if !recordFileExists[keyType] {
				defects = append(defects, fmt.Sprintf("template %q has no state record", name))
				continue
			}
			// Disabled templates are skipped by registration, so their
			// content is otherwise never checked. Enabled templates were
			// just loaded; invalid records are reported separately.
			if recordStates[keyType] == keytypestate.StateDisabled {
				if _, err := templatestore.LoadTemplateFromPath(filepath.Join(dir, name), masterKey); err != nil {
					defects = append(defects, fmt.Sprintf("disabled template %q failed validation: %v", name, err))
				}
			}
		default:
			defects = append(defects, fmt.Sprintf("unexpected entry %q", name))
		}
	}
	return defects
}

func registerTemplateRecord(active storepaths.ActivePaths, identityID string, masterKey []byte, rec keytypestate.Record, registrar TemplateRegistrar) templatepolicy.RegistrationOutcome {
	var outcome templatepolicy.RegistrationOutcome
	path := templatestore.GetTemplateFilePathActive(active, rec.KeyType, registrar.TemplateType)
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
		recordProviderOwner(identityID, rec.KeyType)
		outcome.IdempotentKeyTypes = append(outcome.IdempotentKeyTypes, rec.KeyType)
		return outcome
	}

	if existing := lsigprovider.Get(rec.KeyType); existing != nil {
		existingFingerprint, ok := lsigprovider.CompatibilityFingerprintOf(existing)
		// Both fingerprints are computed by this binary (same fingerprint
		// version), so this is always a same-version comparison; routing it
		// through the shared helper keeps it consistent and future-proof if
		// either side is ever sourced from durable storage.
		if match, comparable := lsigprovider.FingerprintsMatch(existingFingerprint, incomingFingerprint); ok && comparable && match {
			recordProviderOwner(identityID, rec.KeyType)
			outcome.IdempotentKeyTypes = append(outcome.IdempotentKeyTypes, rec.KeyType)
		} else {
			outcome.ConflictingKeyTypes = append(outcome.ConflictingKeyTypes, rec.KeyType)
		}
		return outcome
	}

	if !registerProviderForOwner(identityID, rec.KeyType, prepared.Register) {
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
		// Only a same-version, different-hash pair is a real conflict; a
		// cross-version or unparseable stored fingerprint is treated as
		// idempotent (benign) so a formula bump cannot false-conflict.
		if match, comparable := lsigprovider.FingerprintsMatch(rec.Fingerprint, registryFingerprint); comparable && !match {
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
