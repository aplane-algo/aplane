// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package templatestore provides common utilities for storing and loading
// encrypted YAML template files in the keystore.
//
// This package is used by both:
//   - lsig/generictemplate: Generic LogicSig templates (TEAL-only)
//   - composeddsa-backed templates: DSA composition templates
//
// Templates are stored as encrypted YAML files with the .template extension.
package templatestore

import (
	"fmt"
	"os"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keytypefmt"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// BaseTemplateSpec contains fields common to all template types.
// Specific template systems embed this and add their own fields.
type BaseTemplateSpec struct {
	SchemaVersion     int  `yaml:"schema_version"`
	DerivationVersion *int `yaml:"derivation_version"`

	TemplateType string `yaml:"template_type"` // "generic" or "composed" (optional, aids detection)
	BaseKeyType  string `yaml:"base_key_type"`
	Publisher    string `yaml:"publisher"`
	Family       string `yaml:"family"`
	Version      int    `yaml:"version"`
	DisplayName  string `yaml:"display_name"`
	Description  string `yaml:"description"`
	DisplayColor string `yaml:"display_color"`
}

const (
	// DerivationVersionPushbytes is the legacy template derivation layout that
	// uses a generated pushbytes marker followed by pop.
	DerivationVersionPushbytes = 1

	// DerivationVersionTrailingBytecblock uses a dead-code bytecblock after the
	// program's logical exit as the single-byte salt anchor.
	DerivationVersionTrailingBytecblock = 2
)

// KeyType returns the computed key type using publisher.family.vN.
func (s *BaseTemplateSpec) KeyType() string {
	publisher := strings.ToLower(strings.TrimSpace(s.Publisher))
	family := strings.ToLower(strings.TrimSpace(s.Family))
	return fmt.Sprintf("%s.%s.v%d", publisher, family, s.Version)
}

// ValidateBase validates the common fields.
func (s *BaseTemplateSpec) ValidateBase(maxSchemaVersion int) error {
	schemaVersion := s.SchemaVersion
	if schemaVersion == 0 {
		schemaVersion = 1
	}
	if schemaVersion > maxSchemaVersion {
		return fmt.Errorf("schema_version %d is newer than supported version %d", schemaVersion, maxSchemaVersion)
	}
	if s.DerivationVersion != nil {
		switch *s.DerivationVersion {
		case DerivationVersionPushbytes, DerivationVersionTrailingBytecblock:
		default:
			return fmt.Errorf("derivation_version %d is not supported", *s.DerivationVersion)
		}
	}
	if s.Family == "" {
		return fmt.Errorf("family is required")
	}
	if s.Publisher == "" {
		return fmt.Errorf("publisher is required")
	}
	if !keytypefmt.ValidSegment(strings.ToLower(strings.TrimSpace(s.Publisher))) {
		return fmt.Errorf("publisher contains unsafe characters")
	}
	if !keytypefmt.ValidSegment(strings.ToLower(strings.TrimSpace(s.Family))) {
		return fmt.Errorf("family contains unsafe characters")
	}
	if s.Version < 1 {
		return fmt.Errorf("version must be >= 1")
	}
	if s.DisplayName == "" {
		return fmt.Errorf("display_name is required")
	}
	return nil
}

// TemplateType identifies the type of template.
type TemplateType string

const (
	// TemplateTypeGeneric is for generic LogicSig templates.
	TemplateTypeGeneric TemplateType = "generic"
	// TemplateTypeComposed is for DSA composition templates.
	TemplateTypeComposed TemplateType = "composed"
)

// ValidateBaseKeyType validates the relationship between template_type and
// base_key_type.
func ValidateBaseKeyType(templateType TemplateType, baseKeyType string) error {
	baseKeyType = strings.TrimSpace(baseKeyType)
	switch templateType {
	case "", TemplateTypeGeneric:
		if baseKeyType != "" {
			return fmt.Errorf("base_key_type must not be set for generic templates")
		}
	case TemplateTypeComposed:
		if baseKeyType == "" {
			return fmt.Errorf("base_key_type is required for composed templates")
		}
	default:
		return fmt.Errorf("unsupported template_type %q", templateType)
	}
	return nil
}

// ActiveTemplateTypes returns template types that are loaded from identity
// storage in the current schema.
func ActiveTemplateTypes() []TemplateType {
	return []TemplateType{TemplateTypeGeneric, TemplateTypeComposed}
}

func GetTemplateDirForPaths(paths storepaths.Paths, identityID string, templateType TemplateType) string {
	return paths.KeyTypeRecordsDir(identityID)
}

func GetTemplateFilePathForPaths(paths storepaths.Paths, identityID, keyType string, templateType TemplateType) (string, error) {
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		return "", err
	}
	return GetTemplateFilePathActive(active, keyType, templateType), nil
}

// GetTemplateFilePathActive is GetTemplateFilePathForPaths against resolved
// active-store paths (generational or legacy).
func GetTemplateFilePathActive(active storepaths.ActivePaths, keyType string, _ TemplateType) string {
	return active.KeyTypeTemplate(normalizeKeyType(keyType))
}

func SaveTemplateForPaths(paths storepaths.Paths, identityID string, yamlData []byte, keyType string, templateType TemplateType, masterKey []byte) (string, error) {
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		return "", err
	}
	return SaveTemplateActive(active, yamlData, keyType, templateType, masterKey)
}

// SaveTemplateActive is SaveTemplateForPaths against resolved active-store
// paths.
func SaveTemplateActive(active storepaths.ActivePaths, yamlData []byte, keyType string, templateType TemplateType, masterKey []byte) (string, error) {
	keyType = normalizeKeyType(keyType)
	if _, ok := sourceForTemplateType(templateType); !ok {
		return "", fmt.Errorf("unsupported template_type %q", templateType)
	}

	// Ensure directory exists
	if err := fsutil.MkdirAll(active.KeyTypeRecordsDir()); err != nil {
		return "", fmt.Errorf("failed to create templates directory: %w", err)
	}

	// Encrypt with master key
	encrypted, err := crypto.EncryptWithMasterKey(yamlData, masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt template: %w", err)
	}

	// Write the file
	outputPath := GetTemplateFilePathActive(active, keyType, templateType)
	if err := fsutil.WriteFile(outputPath, encrypted); err != nil {
		return "", fmt.Errorf("failed to write template file: %w", err)
	}

	return outputPath, nil
}

// LoadTemplateFromPath reads and decrypts a template file from a specific path.
func LoadTemplateFromPath(path string, masterKey []byte) ([]byte, error) {
	return keys.ReadAndDecryptFile(path, masterKey, "template file")
}

func TemplateExistsForPaths(paths storepaths.Paths, identityID, keyType string, templateType TemplateType) bool {
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		return false
	}
	return TemplateExistsActive(active, keyType, templateType)
}

// TemplateExistsActive is TemplateExistsForPaths against resolved
// active-store paths.
func TemplateExistsActive(active storepaths.ActivePaths, keyType string, templateType TemplateType) bool {
	source, sourceOK := sourceForTemplateType(templateType)
	if !sourceOK {
		return false
	}
	rec, ok, err := keytypestate.GetActive(active, keyType)
	if err != nil || !ok || rec.Source != source {
		return false
	}
	path := GetTemplateFilePathActive(active, keyType, templateType)
	_, err = os.Stat(path)
	return err == nil
}

// ScanTemplateFiles scans a template directory and returns file info for each .template file.
type TemplateFileInfo struct {
	KeyType  string // Derived from filename (without .template)
	FilePath string // Full path to the file
}

func ScanTemplateDirectoryForPaths(paths storepaths.Paths, identityID string, templateType TemplateType) ([]TemplateFileInfo, error) {
	source, ok := sourceForTemplateType(templateType)
	if !ok {
		return nil, fmt.Errorf("unsupported template_type %q", templateType)
	}
	records, err := keytypestate.List(paths, identityID)
	if err != nil {
		return nil, err
	}

	var files []TemplateFileInfo
	for _, rec := range records {
		if rec.Source != source {
			continue
		}
		path, err := GetTemplateFilePathForPaths(paths, identityID, rec.KeyType, templateType)
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("failed to inspect template %s: %w", rec.KeyType, err)
		}
		files = append(files, TemplateFileInfo{
			KeyType:  rec.KeyType,
			FilePath: path,
		})
	}

	return files, nil
}

func LoadAllTemplatesForPaths(paths storepaths.Paths, identityID string, templateType TemplateType, masterKey []byte) (map[string][]byte, error) {
	files, err := ScanTemplateDirectoryForPaths(paths, identityID, templateType)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]byte)
	for _, file := range files {
		data, err := LoadTemplateFromPath(file.FilePath, masterKey)
		if err != nil {
			fmt.Printf("Warning: Failed to load template %s: %v\n", file.KeyType, err)
			continue
		}
		result[file.KeyType] = data
	}

	return result, nil
}

func sourceForTemplateType(templateType TemplateType) (keytypestate.Source, bool) {
	switch templateType {
	case TemplateTypeGeneric:
		return keytypestate.SourceYAMLGeneric, true
	case TemplateTypeComposed:
		return keytypestate.SourceYAMLComposed, true
	default:
		return "", false
	}
}

func normalizeKeyType(keyType string) string {
	return strings.ToLower(strings.TrimSpace(keyType))
}
