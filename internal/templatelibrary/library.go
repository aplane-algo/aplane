// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package templatelibrary owns plaintext template library parsing and install
// into the encrypted identity-scoped template store.
package templatelibrary

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/generictemplate"

	"gopkg.in/yaml.v3"
)

type TemplateRef struct {
	KeyType      string
	TemplateType templatestore.TemplateType
}

const TemplateTypeCompiledProvider = "compiled_provider"
const MinImportSchemaVersion = 1

type LibraryTemplate struct {
	KeyType      string
	TemplateType string
	DisplayName  string
	Description  string
	Parameters   []lsigprovider.ParameterDef
	RuntimeArgs  []lsigprovider.RuntimeArgDef
	SourcePath   string
	FileName     string
	Installed    bool
	Enabled      bool
	Conflict     string
	Invalid      string
}

type ParsedTemplate struct {
	TemplateRef
	DisplayName string
	Description string
	Parameters  []lsigprovider.ParameterDef
	RuntimeArgs []lsigprovider.RuntimeArgDef
	SourcePath  string
	YAMLData    []byte
}

type InstallResult struct {
	KeyType       string
	TemplateType  templatestore.TemplateType
	OutputPath    string
	AlreadyExists bool
	StateChanged  bool

	hadPreviousState bool
	previousState    keytypestate.Record
}

type RemoveResult struct {
	KeyType      string
	TemplateType templatestore.TemplateType
	OutputPath   string
	Removed      bool
}

func List(paths storepaths.Paths, identityID string) ([]LibraryTemplate, error) {
	dir := paths.TemplateLibraryDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read template library: %w", err)
		}
	}

	var items []LibraryTemplate
	seen := make(map[TemplateRef][]int)
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "README.md" || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		parsed, err := ParseFile(path)
		item := libraryItemFromParsed(parsed)
		item.SourcePath = path
		item.FileName = entry.Name()
		if err != nil {
			item.Invalid = err.Error()
			items = append(items, item)
			continue
		}

		ref := parsed.TemplateRef
		seen[ref] = append(seen[ref], len(items))
		applyInstallStatus(paths, identityID, parsed, &item)
		items = append(items, item)
	}

	for ref, indexes := range seen {
		if len(indexes) < 2 {
			continue
		}
		msg := fmt.Sprintf("multiple library files declare %s template %s", ref.TemplateType, ref.KeyType)
		for _, idx := range indexes {
			items[idx].Conflict = msg
			items[idx].Installed = false
		}
	}

	installedOnly, err := installedOnlyTemplateItems(paths, identityID, seen)
	if err != nil {
		return nil, err
	}
	items = append(items, installedOnly...)

	compiledProviders, err := compiledProviderLibraryItems(paths, identityID)
	if err != nil {
		return nil, err
	}
	items = append(items, compiledProviders...)

	sort.SliceStable(items, func(i, j int) bool {
		left := sortName(items[i])
		right := sortName(items[j])
		if left == right {
			return items[i].FileName < items[j].FileName
		}
		return left < right
	})

	return items, nil
}

func installedOnlyTemplateItems(paths storepaths.Paths, identityID string, seen map[TemplateRef][]int) ([]LibraryTemplate, error) {
	var items []LibraryTemplate
	for _, templateType := range templatestore.ActiveTemplateTypes() {
		files, err := templatestore.ScanTemplateDirectoryForPaths(paths, identityID, templateType)
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			ref := TemplateRef{KeyType: file.KeyType, TemplateType: templateType}
			if _, ok := seen[ref]; ok {
				continue
			}
			items = append(items, LibraryTemplate{
				KeyType:      file.KeyType,
				TemplateType: string(templateType),
				DisplayName:  file.KeyType,
				Description:  "Installed in this identity; no matching library YAML entry is available.",
				FileName:     filepath.Base(file.FilePath),
				Installed:    true,
				Enabled:      installedRecordEnabled(paths, identityID, file.KeyType),
			})
		}
	}
	return items, nil
}

func ParseFile(path string) (ParsedTemplate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ParsedTemplate{}, fmt.Errorf("failed to read template file: %w", err)
	}
	return ParseYAML(path, data)
}

func ParseFileAs(path string, templateType templatestore.TemplateType) (ParsedTemplate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ParsedTemplate{}, fmt.Errorf("failed to read template file: %w", err)
	}
	return ParseYAMLAs(path, data, templateType)
}

func ParseYAML(path string, data []byte) (ParsedTemplate, error) {
	var header struct {
		templatestore.BaseTemplateSpec `yaml:",inline"`
		TemplateMode                   string `yaml:"template_mode"`
	}
	if err := yaml.Unmarshal(data, &header); err != nil {
		return ParsedTemplate{SourcePath: path}, fmt.Errorf("YAML parse error: %w", err)
	}
	if err := validateBaseImportableSchema(header.BaseTemplateSpec, header.TemplateMode); err != nil {
		return ParsedTemplate{SourcePath: path}, err
	}

	switch templatestore.TemplateType(header.TemplateType) {
	case "", templatestore.TemplateTypeGeneric:
		return parseGeneric(path, data)
	case templatestore.TemplateTypeComposed:
		return parseComposed(path, data)
	default:
		return ParsedTemplate{SourcePath: path}, fmt.Errorf("unsupported template_type %q", header.TemplateType)
	}
}

func ParseYAMLAs(path string, data []byte, templateType templatestore.TemplateType) (ParsedTemplate, error) {
	var header struct {
		templatestore.BaseTemplateSpec `yaml:",inline"`
		TemplateMode                   string `yaml:"template_mode"`
	}
	if err := yaml.Unmarshal(data, &header); err != nil {
		return ParsedTemplate{SourcePath: path}, fmt.Errorf("YAML parse error: %w", err)
	}
	if err := validateBaseImportableSchema(header.BaseTemplateSpec, header.TemplateMode); err != nil {
		return ParsedTemplate{SourcePath: path}, err
	}
	if header.TemplateType != "" && templatestore.TemplateType(header.TemplateType) != templateType {
		return ParsedTemplate{SourcePath: path}, fmt.Errorf("template_type %q does not match requested type %q", header.TemplateType, templateType)
	}
	switch templateType {
	case templatestore.TemplateTypeGeneric:
		return parseGeneric(path, data)
	case templatestore.TemplateTypeComposed:
		return parseComposed(path, data)
	default:
		return ParsedTemplate{SourcePath: path}, fmt.Errorf("unsupported template_type %q", templateType)
	}
}

func ValidateImportableSchema(data []byte) error {
	var header struct {
		templatestore.BaseTemplateSpec `yaml:",inline"`
		TemplateMode                   string `yaml:"template_mode"`
	}
	if err := yaml.Unmarshal(data, &header); err != nil {
		return fmt.Errorf("YAML parse error: %w", err)
	}
	return validateBaseImportableSchema(header.BaseTemplateSpec, header.TemplateMode)
}

func validateBaseImportableSchema(base templatestore.BaseTemplateSpec, templateMode string) error {
	schemaVersion := base.SchemaVersion
	if schemaVersion == 0 {
		schemaVersion = 1
	}
	if schemaVersion < MinImportSchemaVersion {
		return fmt.Errorf("schema_version %d is no longer supported for template import; migrate to schema_version %d",
			schemaVersion, MinImportSchemaVersion)
	}
	if strings.TrimSpace(templateMode) == "" {
		return fmt.Errorf("template_mode is required")
	}
	return nil
}

func InstallParsed(paths storepaths.Paths, identityID string, tmpl ParsedTemplate, masterKey []byte) (InstallResult, error) {
	result := InstallResult{
		KeyType:      tmpl.KeyType,
		TemplateType: tmpl.TemplateType,
	}
	if tmpl.KeyType == "" {
		return result, fmt.Errorf("template key type is required")
	}
	if len(tmpl.YAMLData) == 0 {
		return result, fmt.Errorf("template YAML data is required")
	}

	if templatestore.TemplateExistsForPaths(paths, identityID, tmpl.KeyType, tmpl.TemplateType) {
		result.OutputPath = templatestore.GetTemplateFilePathForPaths(paths, identityID, tmpl.KeyType, tmpl.TemplateType)
		if err := requireInstalledTemplateMatch(result.OutputPath, tmpl, masterKey); err != nil {
			return result, err
		}
		stateChange, err := putTemplateState(paths, identityID, tmpl, keytypestate.StateEnabled)
		if err != nil {
			return result, err
		}
		result.StateChanged = stateChange.Changed
		result.hadPreviousState = stateChange.HadPrevious
		result.previousState = stateChange.Previous
		result.AlreadyExists = true
		return result, nil
	}
	otherType := oppositeTemplateType(tmpl.TemplateType)
	if templatestore.TemplateExistsForPaths(paths, identityID, tmpl.KeyType, otherType) {
		return result, fmt.Errorf("key type %s already exists as a %s template", tmpl.KeyType, otherType)
	}
	if err := validateRegisteredProviderConflict(tmpl); err != nil {
		return result, err
	}

	outputPath, err := templatestore.SaveTemplateForPaths(paths, identityID, tmpl.YAMLData, tmpl.KeyType, tmpl.TemplateType, masterKey)
	if err != nil {
		return result, err
	}
	result.OutputPath = outputPath
	stateChange, err := putTemplateState(paths, identityID, tmpl, keytypestate.StateEnabled)
	if err != nil {
		if rollbackErr := RollbackInstalledTemplateFile(paths, identityID, tmpl.KeyType, tmpl.TemplateType); rollbackErr != nil {
			return result, fmt.Errorf("failed to write template state: %w (rollback failed: %v)", err, rollbackErr)
		}
		return result, err
	}
	result.StateChanged = stateChange.Changed
	result.hadPreviousState = stateChange.HadPrevious
	result.previousState = stateChange.Previous
	return result, nil
}

func requireInstalledTemplateMatch(installedPath string, tmpl ParsedTemplate, masterKey []byte) error {
	existingYAML, err := templatestore.LoadTemplateFromPath(installedPath, masterKey)
	if err != nil {
		return fmt.Errorf("failed to load existing template for compatibility check: %w", err)
	}

	existingFingerprint, err := semanticFingerprint(tmpl.TemplateType, existingYAML)
	if err != nil {
		return fmt.Errorf("failed to fingerprint existing template: %w", err)
	}
	incomingFingerprint, err := semanticFingerprint(tmpl.TemplateType, tmpl.YAMLData)
	if err != nil {
		return fmt.Errorf("failed to fingerprint incoming template: %w", err)
	}
	if existingFingerprint != incomingFingerprint {
		return fmt.Errorf("template conflict for %s: installed template does not match incoming definition", tmpl.KeyType)
	}
	return nil
}

type templateStateChange struct {
	Changed     bool
	HadPrevious bool
	Previous    keytypestate.Record
}

func putTemplateState(paths storepaths.Paths, identityID string, tmpl ParsedTemplate, state keytypestate.State) (templateStateChange, error) {
	fingerprint, err := semanticFingerprint(tmpl.TemplateType, tmpl.YAMLData)
	if err != nil {
		return templateStateChange{}, err
	}
	source, err := stateSourceForTemplateType(tmpl.TemplateType)
	if err != nil {
		return templateStateChange{}, err
	}
	rec := keytypestate.Record{
		KeyType:     tmpl.KeyType,
		Source:      source,
		State:       state,
		Fingerprint: fingerprint,
	}
	existing, ok, err := keytypestate.Get(paths, identityID, tmpl.KeyType)
	if err != nil {
		return templateStateChange{}, err
	}
	change := templateStateChange{HadPrevious: ok, Previous: existing}
	if ok && existing.Source == rec.Source && existing.State == rec.State && existing.Fingerprint == rec.Fingerprint {
		return change, nil
	}
	if ok && existing.ActivatedAt != "" {
		rec.ActivatedAt = existing.ActivatedAt
	}
	change.Changed = true
	return change, keytypestate.Put(paths, identityID, rec)
}

// RollbackTemplateStateChange restores the key type state changed by an
// idempotent template install that did not write a new template file.
func RollbackTemplateStateChange(paths storepaths.Paths, identityID string, result InstallResult) error {
	if !result.StateChanged {
		return nil
	}
	if result.hadPreviousState {
		return keytypestate.Put(paths, identityID, result.previousState)
	}
	return keytypestate.Delete(paths, identityID, result.KeyType)
}

func stateSourceForTemplateType(templateType templatestore.TemplateType) (keytypestate.Source, error) {
	switch templateType {
	case templatestore.TemplateTypeGeneric:
		return keytypestate.SourceYAMLGeneric, nil
	case templatestore.TemplateTypeComposed:
		return keytypestate.SourceYAMLComposed, nil
	default:
		return "", fmt.Errorf("unsupported template_type %q", templateType)
	}
}

func InstallFromLibrary(paths storepaths.Paths, identityID string, ref TemplateRef, masterKey []byte) (InstallResult, error) {
	matches, err := findLibraryMatches(paths, ref)
	if err != nil {
		return InstallResult{KeyType: ref.KeyType, TemplateType: ref.TemplateType}, err
	}
	if len(matches) == 0 {
		return InstallResult{KeyType: ref.KeyType, TemplateType: ref.TemplateType}, fmt.Errorf("template %s (%s) not found in library", ref.KeyType, ref.TemplateType)
	}
	if len(matches) > 1 {
		return InstallResult{KeyType: ref.KeyType, TemplateType: ref.TemplateType}, fmt.Errorf("multiple library files declare %s template %s", ref.TemplateType, ref.KeyType)
	}
	return InstallParsed(paths, identityID, matches[0], masterKey)
}

func ActivateCompiledProvider(paths storepaths.Paths, identityID, keyType string) (InstallResult, error) {
	result := InstallResult{
		KeyType: strings.ToLower(strings.TrimSpace(keyType)),
	}
	if result.KeyType == "" {
		return result, fmt.Errorf("key type is required")
	}
	if !keytypecatalog.IsLibraryVisible(result.KeyType) {
		return result, fmt.Errorf("key type %s is not library-visible", result.KeyType)
	}
	if !lsigprovider.Has(result.KeyType) {
		return result, fmt.Errorf("key type %s is not registered", result.KeyType)
	}
	rec, ok, err := keytypestate.Get(paths, identityID, result.KeyType)
	if err != nil {
		return result, err
	}
	fingerprint := compiledProviderFingerprint(result.KeyType)
	if ok {
		if rec.Source != keytypestate.SourceCompiled {
			return result, fmt.Errorf("key type %s is already installed from source %q", result.KeyType, rec.Source)
		}
		if rec.State == keytypestate.StateEnabled && rec.Fingerprint == fingerprint {
			result.OutputPath = paths.KeyTypeRecord(identityID, result.KeyType)
			result.AlreadyExists = true
			return result, nil
		}
		rec.State = keytypestate.StateEnabled
		rec.Fingerprint = fingerprint
		if err := keytypestate.Put(paths, identityID, rec); err != nil {
			return result, err
		}
		result.OutputPath = paths.KeyTypeRecord(identityID, result.KeyType)
		return result, nil
	}
	if err := keytypestate.Put(paths, identityID, keytypestate.Record{
		KeyType:     result.KeyType,
		Source:      keytypestate.SourceCompiled,
		State:       keytypestate.StateEnabled,
		Fingerprint: fingerprint,
	}); err != nil {
		return result, err
	}
	result.OutputPath = paths.KeyTypeRecord(identityID, result.KeyType)
	return result, nil
}

func DeactivateCompiledProvider(paths storepaths.Paths, identityID, keyType string, masterKey []byte) (RemoveResult, error) {
	result := RemoveResult{
		KeyType: strings.ToLower(strings.TrimSpace(keyType)),
	}
	if result.KeyType == "" {
		return result, fmt.Errorf("key type is required")
	}
	result.OutputPath = paths.KeyTypeRecord(identityID, result.KeyType)
	if err := keytypestate.RequireUnused(paths, identityID, result.KeyType, masterKey); err != nil {
		return result, err
	}
	_, ok, err := keytypestate.Get(paths, identityID, result.KeyType)
	if err != nil {
		return result, err
	}
	if !ok {
		return result, nil
	}
	if err := keytypestate.Delete(paths, identityID, result.KeyType); err != nil {
		return result, err
	}
	result.Removed = true
	return result, nil
}

func EnableInstalledTemplate(paths storepaths.Paths, identityID, keyType string, templateType templatestore.TemplateType) (InstallResult, error) {
	result := InstallResult{
		KeyType:      strings.ToLower(strings.TrimSpace(keyType)),
		TemplateType: templateType,
	}
	if result.KeyType == "" {
		return result, fmt.Errorf("key type is required")
	}
	result.OutputPath = templatestore.GetTemplateFilePathForPaths(paths, identityID, result.KeyType, templateType)
	if !templatestore.TemplateExistsForPaths(paths, identityID, result.KeyType, templateType) {
		return result, fmt.Errorf("template %s is not installed", result.KeyType)
	}
	rec, ok, err := keytypestate.Get(paths, identityID, result.KeyType)
	if err != nil {
		return result, err
	}
	if !ok {
		return result, fmt.Errorf("template state %s is not installed", result.KeyType)
	}
	if rec.State == keytypestate.StateEnabled {
		result.AlreadyExists = true
		return result, nil
	}
	rec.State = keytypestate.StateEnabled
	if err := keytypestate.Put(paths, identityID, rec); err != nil {
		return result, err
	}
	result.OutputPath = paths.KeyTypeRecord(identityID, result.KeyType)
	return result, nil
}

func DisableInstalledTemplate(paths storepaths.Paths, identityID, keyType string, templateType templatestore.TemplateType, masterKey []byte) (RemoveResult, error) {
	result := RemoveResult{
		KeyType:      strings.ToLower(strings.TrimSpace(keyType)),
		TemplateType: templateType,
	}
	if result.KeyType == "" {
		return result, fmt.Errorf("key type is required")
	}
	result.OutputPath = templatestore.GetTemplateFilePathForPaths(paths, identityID, result.KeyType, templateType)
	if !templatestore.TemplateExistsForPaths(paths, identityID, result.KeyType, templateType) {
		return result, fmt.Errorf("template %s is not installed", result.KeyType)
	}
	rec, ok, err := keytypestate.Get(paths, identityID, result.KeyType)
	if err != nil {
		return result, err
	}
	if !ok {
		return result, fmt.Errorf("template state %s is not installed", result.KeyType)
	}
	if rec.State == keytypestate.StateDisabled {
		result.OutputPath = paths.KeyTypeRecord(identityID, result.KeyType)
		return result, nil
	}
	if err := keytypestate.RequireUnused(paths, identityID, result.KeyType, masterKey); err != nil {
		return result, err
	}
	rec.State = keytypestate.StateDisabled
	if err := keytypestate.Put(paths, identityID, rec); err != nil {
		return result, err
	}
	result.OutputPath = paths.KeyTypeRecord(identityID, result.KeyType)
	result.Removed = true
	return result, nil
}

func RemoveInstalledTemplate(paths storepaths.Paths, identityID, keyType string, templateType templatestore.TemplateType, masterKey []byte) (RemoveResult, error) {
	result := RemoveResult{
		KeyType:      strings.ToLower(strings.TrimSpace(keyType)),
		TemplateType: templateType,
	}
	if result.KeyType == "" {
		return result, fmt.Errorf("key type is required")
	}
	switch templateType {
	case templatestore.TemplateTypeGeneric, templatestore.TemplateTypeComposed:
	default:
		return result, fmt.Errorf("unsupported template type: %s", templateType)
	}

	path := templatestore.GetTemplateFilePathForPaths(paths, identityID, result.KeyType, templateType)
	result.OutputPath = path
	if !templatestore.TemplateExistsForPaths(paths, identityID, result.KeyType, templateType) {
		return result, nil
	}
	if err := keytypestate.RequireUnused(paths, identityID, result.KeyType, masterKey); err != nil {
		return result, err
	}
	rec, hadState, err := keytypestate.Get(paths, identityID, result.KeyType)
	if err != nil {
		return result, err
	}
	if err := keytypestate.Delete(paths, identityID, result.KeyType); err != nil {
		return result, err
	}
	archivePath, err := archiveInstalled(paths, identityID, result.KeyType, templateType)
	if err != nil {
		if hadState {
			if rollbackErr := keytypestate.Put(paths, identityID, rec); rollbackErr != nil {
				return result, fmt.Errorf("%w (state rollback failed: %v)", err, rollbackErr)
			}
		}
		return result, err
	}
	result.OutputPath = archivePath
	result.Removed = true
	return result, nil
}

// RollbackInstalledTemplateFile removes only the newly written encrypted
// template file. It deliberately leaves key type state rollback to
// RollbackTemplateStateChange.
func RollbackInstalledTemplateFile(paths storepaths.Paths, identityID, keyType string, templateType templatestore.TemplateType) error {
	path := templatestore.GetTemplateFilePathForPaths(paths, identityID, keyType, templateType)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove installed template: %w", err)
	}
	return nil
}

func archiveInstalled(paths storepaths.Paths, identityID, keyType string, templateType templatestore.TemplateType) (string, error) {
	sourcePath := templatestore.GetTemplateFilePathForPaths(paths, identityID, keyType, templateType)
	deletedKeysDir := paths.DeletedKeysDir(identityID)
	deletedTemplatePath := paths.DeletedKeyTypeTemplate(identityID, keyType)
	if err := fsutil.MkdirAll(deletedKeysDir); err != nil {
		return "", fmt.Errorf("failed to create deleted keys directory: %w", err)
	}
	if err := fsutil.MkdirAll(filepath.Dir(deletedTemplatePath)); err != nil {
		return "", fmt.Errorf("failed to create deleted templates directory: %w", err)
	}
	if err := os.Rename(sourcePath, deletedTemplatePath); err != nil {
		return "", fmt.Errorf("failed to move installed template: %w", err)
	}
	return deletedTemplatePath, nil
}

func parseGeneric(path string, data []byte) (ParsedTemplate, error) {
	spec, err := generictemplate.ParseTemplateSpec(data)
	if err != nil {
		return ParsedTemplate{SourcePath: path}, fmt.Errorf("failed to parse generic template: %w", err)
	}
	if err := generictemplate.ValidateSpec(spec); err != nil {
		return ParsedTemplate{SourcePath: path}, fmt.Errorf("invalid generic template: %w", err)
	}
	return ParsedTemplate{
		TemplateRef: TemplateRef{
			KeyType:      spec.KeyType(),
			TemplateType: templatestore.TemplateTypeGeneric,
		},
		DisplayName: spec.DisplayName,
		Description: spec.Description,
		Parameters:  generictemplate.ParameterSpecToParameterDefs(spec.Parameters),
		RuntimeArgs: generictemplate.RuntimeArgSpecToRuntimeArgDefs(spec.RuntimeArgs),
		SourcePath:  path,
		YAMLData:    append([]byte(nil), data...),
	}, nil
}

func parseComposed(path string, data []byte) (ParsedTemplate, error) {
	spec, err := composeddsa.ParseTemplateSpec(data)
	if err != nil {
		return ParsedTemplate{SourcePath: path}, fmt.Errorf("failed to parse composed template: %w", err)
	}
	if err := composeddsa.ValidateTemplateSpec(spec); err != nil {
		return ParsedTemplate{SourcePath: path}, fmt.Errorf("invalid composed template: %w", err)
	}
	return ParsedTemplate{
		TemplateRef: TemplateRef{
			KeyType:      spec.KeyType(),
			TemplateType: templatestore.TemplateTypeComposed,
		},
		DisplayName: spec.DisplayName,
		Description: spec.Description,
		Parameters:  generictemplate.ParameterSpecToParameterDefs(spec.Parameters),
		RuntimeArgs: generictemplate.RuntimeArgSpecToRuntimeArgDefs(spec.RuntimeArgs),
		SourcePath:  path,
		YAMLData:    append([]byte(nil), data...),
	}, nil
}

func applyInstallStatus(paths storepaths.Paths, identityID string, parsed ParsedTemplate, item *LibraryTemplate) {
	if item.KeyType == "" || item.Invalid != "" {
		return
	}
	if templatestore.TemplateExistsForPaths(paths, identityID, item.KeyType, parsed.TemplateType) {
		item.Installed = true
		item.Enabled = installedRecordEnabled(paths, identityID, item.KeyType)
		return
	}
	otherType := oppositeTemplateType(parsed.TemplateType)
	if templatestore.TemplateExistsForPaths(paths, identityID, item.KeyType, otherType) {
		item.Conflict = fmt.Sprintf("key type already installed as a %s template", otherType)
		return
	}
	if err := validateRegisteredProviderConflict(parsed); err != nil {
		item.Conflict = err.Error()
	}
}

func validateRegisteredProviderConflict(tmpl ParsedTemplate) error {
	if !lsigprovider.Has(tmpl.KeyType) {
		return nil
	}
	incomingFingerprint, err := semanticFingerprint(tmpl.TemplateType, tmpl.YAMLData)
	if err != nil {
		return fmt.Errorf("failed to fingerprint template %s: %w", tmpl.KeyType, err)
	}
	existing := lsigprovider.Get(tmpl.KeyType)
	if existingFingerprint, ok := lsigprovider.CompatibilityFingerprintOf(existing); ok && existingFingerprint == incomingFingerprint {
		return nil
	} else if ok {
		return fmt.Errorf("key type %s is already registered by a conflicting provider", tmpl.KeyType)
	}
	return fmt.Errorf("key type %s is already registered as a built-in provider", tmpl.KeyType)
}

func semanticFingerprint(templateType templatestore.TemplateType, data []byte) (string, error) {
	switch templateType {
	case templatestore.TemplateTypeGeneric:
		return generictemplate.SemanticFingerprint(data)
	case templatestore.TemplateTypeComposed:
		return composeddsa.SemanticFingerprint(data)
	default:
		return "", fmt.Errorf("unsupported template_type %q", templateType)
	}
}

func findLibraryMatches(paths storepaths.Paths, ref TemplateRef) ([]ParsedTemplate, error) {
	dir := paths.TemplateLibraryDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read template library: %w", err)
	}

	var matches []ParsedTemplate
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "README.md" || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		parsed, err := ParseFile(path)
		if err != nil {
			continue
		}
		if parsed.KeyType == ref.KeyType && parsed.TemplateType == ref.TemplateType {
			matches = append(matches, parsed)
		}
	}
	return matches, nil
}

// FindLibraryYAML returns the raw plaintext YAML and source path for a library
// entry matching ref. Returns os.ErrNotExist if the library has no entry for
// that key type and template type.
func FindLibraryYAML(paths storepaths.Paths, ref TemplateRef) ([]byte, string, error) {
	matches, err := findLibraryMatches(paths, ref)
	if err != nil {
		return nil, "", err
	}
	if len(matches) == 0 {
		return nil, "", fmt.Errorf("library has no entry for %s (%s): %w", ref.KeyType, ref.TemplateType, os.ErrNotExist)
	}
	if len(matches) > 1 {
		paths := make([]string, 0, len(matches))
		for _, m := range matches {
			paths = append(paths, m.SourcePath)
		}
		return nil, "", fmt.Errorf("library has multiple entries for %s (%s): %s", ref.KeyType, ref.TemplateType, strings.Join(paths, ", "))
	}
	return matches[0].YAMLData, matches[0].SourcePath, nil
}

func libraryItemFromParsed(parsed ParsedTemplate) LibraryTemplate {
	return LibraryTemplate{
		KeyType:      parsed.KeyType,
		TemplateType: string(parsed.TemplateType),
		DisplayName:  parsed.DisplayName,
		Description:  parsed.Description,
		Parameters:   parsed.Parameters,
		RuntimeArgs:  parsed.RuntimeArgs,
		SourcePath:   parsed.SourcePath,
	}
}

func compiledProviderLibraryItems(paths storepaths.Paths, identityID string) ([]LibraryTemplate, error) {
	records, err := keytypestate.List(paths, identityID)
	if err != nil {
		return nil, err
	}
	installedSet := make(map[string]bool, len(records))
	enabledSet := make(map[string]bool, len(records))
	for _, rec := range records {
		if rec.Source != keytypestate.SourceCompiled {
			continue
		}
		installedSet[rec.KeyType] = true
		if rec.State == keytypestate.StateEnabled {
			enabledSet[rec.KeyType] = true
		}
	}

	entries := keytypecatalog.LibraryVisible()
	items := make([]LibraryTemplate, 0, len(entries))
	for _, entry := range entries {
		item := LibraryTemplate{
			KeyType:      entry.KeyType,
			TemplateType: TemplateTypeCompiledProvider,
			Installed:    installedSet[entry.KeyType],
			Enabled:      enabledSet[entry.KeyType],
		}
		provider := lsigprovider.Get(entry.KeyType)
		if provider == nil {
			item.Invalid = fmt.Sprintf("key type %s is cataloged but not registered", entry.KeyType)
		} else {
			item.DisplayName = provider.DisplayName()
			item.Description = provider.Description()
			item.Parameters = provider.CreationParams()
			item.RuntimeArgs = provider.RuntimeArgs()
		}
		items = append(items, item)
	}
	return items, nil
}

func installedRecordEnabled(paths storepaths.Paths, identityID, keyType string) bool {
	rec, ok, err := keytypestate.Get(paths, identityID, keyType)
	return err == nil && ok && rec.State == keytypestate.StateEnabled
}

func compiledProviderFingerprint(keyType string) string {
	provider := lsigprovider.Get(keyType)
	if provider == nil {
		return ""
	}
	fingerprint, _ := lsigprovider.CompatibilityFingerprintOf(provider)
	return fingerprint
}

func sortName(item LibraryTemplate) string {
	if item.DisplayName != "" {
		return strings.ToLower(item.DisplayName)
	}
	if item.KeyType != "" {
		return strings.ToLower(item.KeyType)
	}
	return strings.ToLower(item.FileName)
}

func oppositeTemplateType(templateType templatestore.TemplateType) templatestore.TemplateType {
	if templateType == templatestore.TemplateTypeGeneric {
		return templatestore.TemplateTypeComposed
	}
	if templateType == templatestore.TemplateTypeComposed {
		return templatestore.TemplateTypeGeneric
	}
	return templatestore.TemplateTypeGeneric
}

func EnsureLibraryDir(paths storepaths.Paths) error {
	return fsutil.MkdirAll(paths.TemplateLibraryDir())
}
