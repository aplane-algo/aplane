// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templates

import (
	"fmt"
	"github.com/aplane-algo/aplane/internal/crypto"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatelibrary"
	"github.com/aplane-algo/aplane/internal/templatepolicy"
	"github.com/aplane-algo/aplane/internal/templatespec"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

type PrepareFunc func(keyType string, data []byte) (templatepolicy.PreparedTemplateRegistration, error)

type TemplateRegistrar struct {
	Name         string
	Source       keytypestate.Source
	TemplateType templatespec.TemplateType
	Prepare      PrepareFunc
}

// ContentDefectKeyTypes lists key types whose durable store content is
// malformed, unreadable, missing, or externally edited: invalid templates,
// invalid state records, orphaned records (state without a template file),
// and fingerprint mismatches. Registration-semantics categories (conflicts
// with process-global providers, idempotent re-registration, disabled
// records) are deliberately excluded — they are not store corruption. On a
// generation-based store any entry here fails the selected generation's
// validation (docs/ARCH_STORE.md, "Runtime reload behavior").
func (r RegistrationReport) ContentDefectKeyTypes() []string {
	defects := r.ContentDefectsExcept(nil)
	texts := make([]string, len(defects))
	for i, defect := range defects {
		texts[i] = defect.Text
	}
	return texts
}

// ContentDefect is one content defect. Text is the key type, or the
// namespace defect's description; Entry, for a namespace defect about one
// entry of the keytypes namespace, is that entry's name.
type ContentDefect struct {
	Text  string
	Entry string
}

// ContentDefectsExcept is ContentDefectKeyTypes without the record defects
// (RecordDefects) of the key types a template repair replaces. Every other
// defect stays, the repaired key types' other defects included.
func (r RegistrationReport) ContentDefectsExcept(repaired map[string]bool) []ContentDefect {
	var defects []ContentDefect
	for _, bucket := range [][]string{
		r.GenericInvalidKeyTypes,
		r.ComposedInvalidKeyTypes,
		r.InvalidStateRecordKeyTypes,
		r.CompiledInvalidKeyTypes,
	} {
		for _, keyType := range bucket {
			defects = append(defects, ContentDefect{Text: keyType})
		}
	}
	for _, defect := range r.RecordDefects() {
		if !repaired[defect.KeyType] {
			defects = append(defects, ContentDefect{Text: defect.KeyType})
		}
	}
	for _, defect := range r.NamespaceDefects {
		defects = append(defects, ContentDefect(defect))
	}
	return defects
}

// NamespaceDefect is a content problem the keytypes namespace sweep found.
// Entry names the entry it is about, or is empty for one about the whole
// namespace.
type NamespaceDefect struct {
	Text  string
	Entry string
}

// RecordDefectKind is a template record defect: a content defect that leaves
// the record and its template file each readable, so a template repair can
// re-pin or remove the record instead of rebuilding the store.
type RecordDefectKind string

const (
	// RecordExternalEdit is an enabled record whose fingerprint is not the
	// one its stored template computes.
	RecordExternalEdit RecordDefectKind = "external edit"
	// RecordOrphaned is an enabled record with no template file.
	RecordOrphaned RecordDefectKind = "orphaned record"
	// RecordDisabledOrphaned is a disabled record with no template file.
	RecordDisabledOrphaned RecordDefectKind = "disabled record without template file"
)

// RecordDefect is one template record defect, by key type. TemplateType is
// the record's for an enabled record; a disabled record's is not reported.
type RecordDefect struct {
	KeyType      string
	Kind         RecordDefectKind
	TemplateType templatespec.TemplateType
}

// RecordDefects lists the template record defects among the content defects,
// in ContentDefectKeyTypes order.
func (r RegistrationReport) RecordDefects() []RecordDefect {
	var defects []RecordDefect
	for _, bucket := range []struct {
		keyTypes     []string
		kind         RecordDefectKind
		templateType templatespec.TemplateType
	}{
		{r.GenericOrphanedKeyTypes, RecordOrphaned, templatespec.TemplateTypeGeneric},
		{r.ComposedOrphanedKeyTypes, RecordOrphaned, templatespec.TemplateTypeComposed},
		{r.GenericExternalEditKeyTypes, RecordExternalEdit, templatespec.TemplateTypeGeneric},
		{r.ComposedExternalEditKeyTypes, RecordExternalEdit, templatespec.TemplateTypeComposed},
		{r.DisabledOrphanedKeyTypes, RecordDisabledOrphaned, ""},
	} {
		for _, keyType := range bucket.keyTypes {
			defects = append(defects, RecordDefect{KeyType: keyType, Kind: bucket.kind, TemplateType: bucket.templateType})
		}
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
	NamespaceDefects []NamespaceDefect
	// DisabledOrphanedKeyTypes are disabled YAML records with no template
	// file, which the namespace sweep finds: registration's orphan buckets
	// hold enabled records only.
	DisabledOrphanedKeyTypes []string

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

// repairHint is what repairs a template record defect. It works whether the
// defect was found at unlock, which leaves the store in recovery, or by a
// reload of an unlocked signer.
const repairHint = "(stop apsigner and repair with `apstore template repair`; see docs/USER_KEYTYPES.md)"

func (r RegistrationReport) Warnings() []string {
	var warnings []string
	for _, defect := range r.NamespaceDefects {
		warnings = append(warnings, fmt.Sprintf("keytypes namespace defect: %s", defect.Text))
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
		warnings = append(warnings, fmt.Sprintf("conflicting compiled key type records ignored on reload: %v (re-pin each with `apadmin keytype enable <key_type>`)", r.CompiledConflictingKeyTypes))
	}
	if len(r.GenericExternalEditKeyTypes) > 0 {
		warnings = append(warnings, fmt.Sprintf("externally edited generic templates ignored on reload: %v "+repairHint, r.GenericExternalEditKeyTypes))
	}
	if len(r.ComposedExternalEditKeyTypes) > 0 {
		warnings = append(warnings, fmt.Sprintf("externally edited composed templates ignored on reload: %v "+repairHint, r.ComposedExternalEditKeyTypes))
	}
	if len(r.GenericOrphanedKeyTypes) > 0 {
		warnings = append(warnings, fmt.Sprintf("generic template state records without template files ignored on reload: %v "+repairHint, r.GenericOrphanedKeyTypes))
	}
	if len(r.ComposedOrphanedKeyTypes) > 0 {
		warnings = append(warnings, fmt.Sprintf("composed template state records without template files ignored on reload: %v "+repairHint, r.ComposedOrphanedKeyTypes))
	}
	if len(r.DisabledOrphanedKeyTypes) > 0 {
		warnings = append(warnings, fmt.Sprintf("disabled template state records without template files: %v "+repairHint, r.DisabledOrphanedKeyTypes))
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

// ProviderRegistry is the LogicSig provider registry a reload registers its
// templates in and reads the providers registered before it from. The
// runtime hands it over (productruntime.Runtime.ProviderRegistry); the reload
// reaches the registry through it alone, so a registry per identity can
// replace the process-wide one without touching the reload.
type ProviderRegistry interface {
	Get(keyType string) lsigprovider.LSigProvider
	RegisterBatchIfAbsent(batch []lsigprovider.LSigProvider) ([]bool, error)
	Unregister(keyType string) bool
}

// Manager owns keystore template registration ordering for signer reloads.
type Manager struct {
	Paths       storepaths.Paths
	ActivePaths storepaths.GenPaths
	Registrars  []TemplateRegistrar
	Registry    ProviderRegistry
}

// NewManager is a manager over paths that registers in registry.
func NewManager(paths storepaths.Paths, registry ProviderRegistry) *Manager {
	return &Manager{
		Paths:      paths,
		Registrars: DefaultTemplateRegistrars(),
		Registry:   registry,
	}
}

func DefaultTemplateRegistrars() []TemplateRegistrar {
	return []TemplateRegistrar{
		{
			Name:         "generic",
			Source:       keytypestate.SourceYAMLGeneric,
			TemplateType: templatespec.TemplateTypeGeneric,
			Prepare:      generictemplate.PrepareKeystoreTemplateRegistration,
		},
		{
			Name:         "composed",
			Source:       keytypestate.SourceYAMLComposed,
			TemplateType: templatespec.TemplateTypeComposed,
			Prepare:      composeddsa.PrepareKeystoreTemplateRegistration,
		},
	}
}

// RegisterKeystoreTemplates prepares and registers all keystore-backed template
// families in one call, for offline tooling and tests. Runtime reloads use
// PrepareKeystoreTemplates during Build, scan keys before registration using
// stored key metadata (sized through the key type's provider if it is already
// registered, and through its base key type otherwise), and register the
// prepared batch at publish. Recoverable reload problems are surfaced through
// the returned report; the error return is reserved for manager
// misconfiguration and unrecoverable work that should stop the caller's reload
// flow.
func (m *Manager) RegisterKeystoreTemplates(kr *crypto.Keyring) (RegistrationReport, error) {
	prepared, err := m.PrepareKeystoreTemplates(kr)
	if err != nil {
		return prepared.report, err
	}
	return prepared.Register(m.Registry), nil
}

// PreparedTemplates is a reload's templates prepared and checked, with
// nothing registered: the report of every outcome but the registration's,
// and the providers to activate.
type PreparedTemplates struct {
	report  RegistrationReport
	pending []pendingRegistration
}

// Report is the preparation's report. It holds every content defect: the
// registration only decides whether a template it activates is activated
// or conflicting.
func (p PreparedTemplates) Report() RegistrationReport { return p.report }

// Register registers the prepared providers as one batch in registry and
// returns the whole report. It cannot fail: every provider kept the
// contract at preparation, which the batch checks again. A batch that
// refused one anyway would register nothing, and every template it held is
// reported conflicting, so none of them signs.
func (p PreparedTemplates) Register(registry ProviderRegistry) RegistrationReport {
	report := p.report
	if err := registerPending(&report, registry, p.pending); err != nil {
		for _, pending := range p.pending {
			appendOutcome(&report, pending.source, templatepolicy.RegistrationOutcome{ConflictingKeyTypes: []string{pending.keyType}})
		}
	}
	return report
}

// PrepareKeystoreTemplates prepares every keystore template and checks it,
// as RegisterKeystoreTemplates does, and registers nothing: a reload's
// Build prepares, and its Publish registers (PreparedTemplates.Register).
func (m *Manager) PrepareKeystoreTemplates(kr *crypto.Keyring) (PreparedTemplates, error) {
	return m.processKeystoreTemplates(kr, true)
}

// ValidateKeystoreTemplates executes the same durable-content gates as
// RegisterKeystoreTemplates without mutating the process-global provider
// registry. Generation transactions use it before the store-root commit so a
// validly encrypted but semantically broken candidate can never become
// authoritative.
func (m *Manager) ValidateKeystoreTemplates(kr *crypto.Keyring) (RegistrationReport, error) {
	prepared, err := m.processKeystoreTemplates(kr, false)
	return prepared.report, err
}

// processKeystoreTemplates prepares every template record. With activate set
// it returns each template to activate as a provider to register; without
// it, as validation does, it reports each one activated.
func (m *Manager) processKeystoreTemplates(kr *crypto.Keyring, activate bool) (PreparedTemplates, error) {
	registrars, err := m.templateRegistrars()
	if err != nil {
		return PreparedTemplates{}, err
	}
	registry := m.Registry

	report := RegistrationReport{}
	// Bind every record and template read to one caller-authenticated
	// generation. The fallback, for an unset ActivePaths, remains for
	// low-level tests until their fixtures are converted; production assembly
	// always supplies ActivePaths.
	active := m.ActivePaths
	if active.GenerationID() == "" {
		var err error
		active, err = genstore.Resolve(m.Paths)
		if err != nil {
			return PreparedTemplates{report: report}, fmt.Errorf("failed to resolve active key store layout: %w", err)
		}
	}
	records, err := keytypestate.ListActive(active)
	if err != nil {
		return PreparedTemplates{report: report}, fmt.Errorf("failed to load keystore templates: %w", err)
	}

	registrarsBySource := make(map[keytypestate.Source]TemplateRegistrar, len(registrars))
	for _, registrar := range registrars {
		registrarsBySource[registrar.Source] = registrar
	}

	// Reload is state-record driven: stray encrypted .template files without a
	// matching key type state record are intentionally invisible. Every
	// template is prepared and checked here; the ones to activate are
	// registered later, as one batch (PreparedTemplates.Register).
	var pending []pendingRegistration
	for _, rec := range records {
		registrar, ok := registrarsBySource[rec.Source]
		if !ok {
			continue
		}
		outcome, provider := processTemplateRecord(active, kr, rec, registrar, registry, activate)
		appendOutcome(&report, registrar.Source, outcome)
		if provider != nil {
			pending = append(pending, pendingRegistration{source: registrar.Source, keyType: rec.KeyType, provider: provider})
		}
	}

	if invalid, listErr := keytypestate.ListInvalidActive(active); listErr == nil {
		report.InvalidStateRecordKeyTypes = append(report.InvalidStateRecordKeyTypes, invalid...)
	}
	// The namespace sweep backs the fail-closed reload gate.
	report.NamespaceDefects, report.DisabledOrphanedKeyTypes = sweepKeyTypeNamespace(active, kr, records, registrarsBySource)

	compiledOutcome := validateCompiledProviderRecords(records, registry)
	report.CompiledIdempotentKeyTypes = append(report.CompiledIdempotentKeyTypes, compiledOutcome.IdempotentKeyTypes...)
	report.CompiledConflictingKeyTypes = append(report.CompiledConflictingKeyTypes, compiledOutcome.ConflictingKeyTypes...)
	report.CompiledInvalidKeyTypes = append(report.CompiledInvalidKeyTypes, compiledOutcome.InvalidKeyTypes...)

	return PreparedTemplates{report: report, pending: pending}, nil
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
// store directly, catching what record-driven registration cannot:
// unexpected entries, template files with no state record or whose record's
// source does not use template files, disabled YAML templates (registration
// never decrypts or parses them), and disabled YAML records whose template
// file is missing (registration's orphan bucket only covers enabled
// records). The expected on-disk pairing comes from each record's source:
// YAML sources own exactly one .template, compiled sources own none.
// Enabled templates and malformed records are already covered by
// registration and ListInvalidActive; the sweep does not re-report them.
// It returns the disabled records without a template file apart, by key
// type, and every other defect as a description. Both feed the fail-closed
// reload gate (docs/ARCH_STORE.md, "Runtime reload behavior").
func sweepKeyTypeNamespace(active storepaths.GenPaths, kr *crypto.Keyring, records []keytypestate.Record, registrarsBySource map[keytypestate.Source]TemplateRegistrar) (defects []NamespaceDefect, disabledOrphaned []string) {
	dir := active.KeyTypeRecordsDir()
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return []NamespaceDefect{{Text: fmt.Sprintf("read keytypes namespace: %v", err)}}, nil
	}
	recordsByKeyType := make(map[string]keytypestate.Record, len(records))
	for _, rec := range records {
		recordsByKeyType[rec.KeyType] = rec
	}
	recordFileExists := make(map[string]bool, len(entries))
	templateFileExists := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		switch {
		case strings.HasSuffix(entry.Name(), ".json"):
			recordFileExists[strings.TrimSuffix(entry.Name(), ".json")] = true
		case strings.HasSuffix(entry.Name(), ".template"):
			templateFileExists[strings.TrimSuffix(entry.Name(), ".template")] = true
		}
	}
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case entry.IsDir():
			defects = append(defects, NamespaceDefect{Text: fmt.Sprintf("unexpected directory %q", name), Entry: name})
		case strings.HasSuffix(name, ".json"):
			// Lookup APIs normalize the key type before reading, so a
			// record whose basename is not already canonical is silently
			// invisible to them — unaccounted content, not "invalid".
			keyType := strings.TrimSuffix(name, ".json")
			if canonical, err := keytypestate.NormalizeKeyType(keyType); err != nil || canonical != keyType {
				defects = append(defects, NamespaceDefect{Text: fmt.Sprintf("record %q does not use a canonical key type filename", name), Entry: name})
			}
			// Record content validity is covered by ListInvalidActive.
		case strings.HasSuffix(name, ".template"):
			keyType := strings.TrimSuffix(name, ".template")
			if canonical, err := keytypestate.NormalizeKeyType(keyType); err != nil || canonical != keyType {
				defects = append(defects, NamespaceDefect{Text: fmt.Sprintf("template %q does not use a canonical key type filename", name), Entry: name})
				continue
			}
			if !recordFileExists[keyType] {
				defects = append(defects, NamespaceDefect{Text: fmt.Sprintf("template %q has no state record", name), Entry: name})
				continue
			}
			rec, ok := recordsByKeyType[keyType]
			if !ok {
				// Record file exists but is invalid; already reported by
				// ListInvalidActive.
				continue
			}
			if rec.Source == keytypestate.SourceCompiled {
				defects = append(defects, NamespaceDefect{Text: fmt.Sprintf("template %q is paired with a compiled-provider record, which does not use template files", name), Entry: name})
				continue
			}
			// Disabled YAML templates are skipped by registration, so their
			// content is otherwise never checked. Run the same decrypt and
			// Prepare validation registration applies to enabled ones —
			// without registering the provider. Enabled templates were just
			// loaded by registration.
			if rec.State == keytypestate.StateDisabled {
				if err := validateTemplateContent(dir, name, keyType, kr, registrarsBySource[rec.Source]); err != nil {
					defects = append(defects, NamespaceDefect{Text: fmt.Sprintf("disabled template %q failed validation: %v", name, err), Entry: name})
				}
			}
		default:
			defects = append(defects, NamespaceDefect{Text: fmt.Sprintf("unexpected entry %q", name), Entry: name})
		}
	}
	// Record-driven pass: a disabled YAML record whose template file is
	// missing is invisible to both the file loop above and registration
	// (whose orphan bucket is enabled-only).
	for _, rec := range records {
		if rec.Source == keytypestate.SourceCompiled || rec.State != keytypestate.StateDisabled {
			continue
		}
		if !templateFileExists[rec.KeyType] {
			disabledOrphaned = append(disabledOrphaned, rec.KeyType)
		}
	}
	sort.Slice(defects, func(i, j int) bool { return defects[i].Text < defects[j].Text })
	return defects, disabledOrphaned
}

// validateTemplateContent decrypts a template file and runs its registrar's
// Prepare validation without registering anything.
func validateTemplateContent(dir, name, keyType string, kr *crypto.Keyring, registrar TemplateRegistrar) error {
	data, err := templatestore.LoadTemplateFromPath(filepath.Join(dir, name), kr)
	if err != nil {
		return err
	}
	if registrar.Prepare == nil {
		return fmt.Errorf("no registrar for source")
	}
	if _, err := registrar.Prepare(keyType, data); err != nil {
		return err
	}
	return nil
}

// pendingRegistration is a prepared template a reload activates, once every
// template has been prepared.
type pendingRegistration struct {
	source   keytypestate.Source
	keyType  string
	provider lsigprovider.LSigProvider
}

// registerPending registers the pending templates as one batch. One whose
// key type another registration took meanwhile is a conflict, as one found
// registered at preparation is.
func registerPending(report *RegistrationReport, registry ProviderRegistry, pending []pendingRegistration) error {
	if len(pending) == 0 {
		return nil
	}
	batch := make([]lsigprovider.LSigProvider, len(pending))
	for i, p := range pending {
		batch[i] = p.provider
	}
	registered, err := registry.RegisterBatchIfAbsent(batch)
	if err != nil {
		return err
	}
	for i, p := range pending {
		var outcome templatepolicy.RegistrationOutcome
		if registered[i] {
			outcome.ActivatedKeyTypes = []string{p.keyType}
		} else {
			outcome.ConflictingKeyTypes = []string{p.keyType}
		}
		appendOutcome(report, p.source, outcome)
	}
	return nil
}

// processTemplateRecord decides one template record's outcome. A template
// to activate, when activate is set, is returned as its provider for the
// caller to register with the rest, its outcome left to that registration.
func processTemplateRecord(active storepaths.GenPaths, kr *crypto.Keyring, rec keytypestate.Record, registrar TemplateRegistrar, registry ProviderRegistry, activate bool) (templatepolicy.RegistrationOutcome, lsigprovider.LSigProvider) {
	var outcome templatepolicy.RegistrationOutcome
	path := templatestore.GetTemplateFilePathActive(active, rec.KeyType)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			if rec.State == keytypestate.StateEnabled {
				outcome.OrphanedKeyTypes = append(outcome.OrphanedKeyTypes, rec.KeyType)
			}
			return outcome, nil
		}
		outcome.InvalidKeyTypes = append(outcome.InvalidKeyTypes, rec.KeyType)
		return outcome, nil
	}
	if rec.State == keytypestate.StateDisabled {
		outcome.DisabledKeyTypes = append(outcome.DisabledKeyTypes, rec.KeyType)
		return outcome, nil
	}

	data, err := templatestore.LoadTemplateFromPath(path, kr)
	if err != nil {
		outcome.InvalidKeyTypes = append(outcome.InvalidKeyTypes, rec.KeyType)
		return outcome, nil
	}
	prepared, err := registrar.Prepare(rec.KeyType, data)
	if err != nil {
		outcome.InvalidKeyTypes = append(outcome.InvalidKeyTypes, rec.KeyType)
		return outcome, nil
	}

	incomingFingerprint := prepared.Fingerprint
	registryFingerprint := ""
	existing := registry.Get(rec.KeyType)
	if existing != nil {
		var ok bool
		registryFingerprint, ok = lsigprovider.CompatibilityFingerprintOf(existing)
		if !ok {
			outcome.ConflictingKeyTypes = append(outcome.ConflictingKeyTypes, rec.KeyType)
			return outcome, nil
		}
	}
	switch keytypestate.CompareForReload(rec, incomingFingerprint, registryFingerprint) {
	case keytypestate.OutcomeExternalEdit:
		outcome.ExternalEditKeyTypes = append(outcome.ExternalEditKeyTypes, rec.KeyType)
		return outcome, nil
	case keytypestate.OutcomeOrphanedRecord:
		outcome.OrphanedKeyTypes = append(outcome.OrphanedKeyTypes, rec.KeyType)
		return outcome, nil
	case keytypestate.OutcomeConflict:
		outcome.ConflictingKeyTypes = append(outcome.ConflictingKeyTypes, rec.KeyType)
		return outcome, nil
	case keytypestate.OutcomeIdempotent:
		outcome.IdempotentKeyTypes = append(outcome.IdempotentKeyTypes, rec.KeyType)
		return outcome, nil
	}

	if existing != nil {
		if registryFingerprint == incomingFingerprint {
			outcome.IdempotentKeyTypes = append(outcome.IdempotentKeyTypes, rec.KeyType)
		} else {
			outcome.ConflictingKeyTypes = append(outcome.ConflictingKeyTypes, rec.KeyType)
		}
		return outcome, nil
	}
	if !activate {
		outcome.ActivatedKeyTypes = append(outcome.ActivatedKeyTypes, rec.KeyType)
		return outcome, nil
	}
	if prepared.Provider == nil {
		outcome.ConflictingKeyTypes = append(outcome.ConflictingKeyTypes, rec.KeyType)
		return outcome, nil
	}
	return outcome, prepared.Provider
}

func validateCompiledProviderRecords(records []keytypestate.Record, registry ProviderRegistry) templatepolicy.RegistrationOutcome {
	var outcome templatepolicy.RegistrationOutcome
	for _, rec := range records {
		if rec.Source != keytypestate.SourceCompiled {
			continue
		}
		if rec.State == keytypestate.StateDisabled {
			outcome.DisabledKeyTypes = append(outcome.DisabledKeyTypes, rec.KeyType)
			continue
		}
		provider := registry.Get(rec.KeyType)
		if provider == nil {
			// Rotating key types are compiled but have no LogicSig provider
			// and no template fingerprint.
			if templatelibrary.RotatingKeyTypeRegistered(rec.KeyType) && rec.Fingerprint == "" {
				outcome.IdempotentKeyTypes = append(outcome.IdempotentKeyTypes, rec.KeyType)
				continue
			}
			outcome.InvalidKeyTypes = append(outcome.InvalidKeyTypes, rec.KeyType)
			continue
		}
		registryFingerprint, _ := lsigprovider.CompatibilityFingerprintOf(provider)
		// A record that pinned nothing is consistent; a pinned fingerprint must
		// be the provider's byte for byte.
		if rec.Fingerprint != "" && rec.Fingerprint != registryFingerprint {
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
