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
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keytypefmt"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// TemplateFileExtension is the suffix every key-type template file carries.
// The name before it is the key type, which is the template's logical
// identity.
const TemplateFileExtension = ".template"

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
	// MaxOpcodeCost is the required, reviewed worst-case cost of every reachable
	// path in the final compiler-returned program.
	MaxOpcodeCost uint64 `yaml:"max_opcode_cost"`
}

const (
	// DerivationVersionPushbytes is the retired template derivation layout that
	// used a generated pushbytes marker followed by pop. It is rejected; the
	// constant survives only so the rejection can name it.
	DerivationVersionPushbytes = 1

	// DerivationVersionTrailingBytecblock is the retired layout that used a
	// dead-code bytecblock after the program's logical exit as the single-byte
	// salt anchor. It is rejected for the same reason as Pushbytes.
	DerivationVersionTrailingBytecblock = 2

	// DerivationVersionAlgodAutoSalt uses TEAL v13 assembler auto-salting. The
	// compiler-returned bytecode is authoritative and is never patched by
	// APlane. It is the only supported derivation contract.
	DerivationVersionAlgodAutoSalt = 3
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
		case DerivationVersionAlgodAutoSalt:
		case DerivationVersionPushbytes, DerivationVersionTrailingBytecblock:
			return fmt.Errorf(
				"derivation_version %d is retired; republish this template with derivation_version %d (TEAL v13 compiler auto-salting)",
				*s.DerivationVersion, DerivationVersionAlgodAutoSalt,
			)
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
	if s.MaxOpcodeCost > lsigresource.MaximumDeclaredOpcodeCost {
		return fmt.Errorf("max_opcode_cost %d exceeds maximum %d", s.MaxOpcodeCost, lsigresource.MaximumDeclaredOpcodeCost)
	}
	return nil
}

// ValidateOpcodeCostDeclaration requires an explicit reviewed ceiling before a
// template can be installed or registered.
func (s *BaseTemplateSpec) ValidateOpcodeCostDeclaration() error {
	if s == nil || s.MaxOpcodeCost == 0 {
		return fmt.Errorf("max_opcode_cost is required and must be greater than zero")
	}
	return nil
}

// LogicSigOpcodeProfile materializes the template's required reviewed ceiling.
// Callers validate the template before using this method.
func (s *BaseTemplateSpec) LogicSigOpcodeProfile(bounded bool) lsigresource.OpcodeProfile {
	if s == nil {
		return lsigresource.OpcodeProfile{}
	}
	if bounded {
		return lsigresource.BoundedOpcodeProfile(s.MaxOpcodeCost, s.MaxOpcodeCost, s.MaxOpcodeCost)
	}
	return lsigresource.DefaultOpcodeProfile(s.MaxOpcodeCost)
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

func SaveTemplateForPaths(paths storepaths.Paths, identityID string, yamlData []byte, keyType string, templateType TemplateType, kr *crypto.Keyring) (string, error) {
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		return "", err
	}
	return SaveTemplateActive(active, yamlData, keyType, templateType, kr)
}

// SaveTemplateActive is SaveTemplateForPaths against resolved active-store
// paths.
func SaveTemplateActive(active storepaths.ActivePaths, yamlData []byte, keyType string, templateType TemplateType, kr *crypto.Keyring) (string, error) {
	keyType = normalizeKeyType(keyType)
	if _, ok := sourceForTemplateType(templateType); !ok {
		return "", fmt.Errorf("unsupported template_type %q", templateType)
	}

	// Ensure directory exists
	if err := fsutil.MkdirAllPrivate(active.KeyTypeRecordsDir()); err != nil {
		return "", fmt.Errorf("failed to create templates directory: %w", err)
	}

	encrypted, err := kr.Seal(yamlData, crypto.KeyTypeTemplateContext(keyType))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt template: %w", err)
	}

	// Write the file
	outputPath := GetTemplateFilePathActive(active, keyType, templateType)
	// Durable, never in-place (docs/ARCH_GENERATIONS.md §4).
	if err := fsutil.WriteFileDurable(outputPath, encrypted); err != nil {
		return "", fmt.Errorf("failed to write template file: %w", err)
	}

	return outputPath, nil
}

// LoadTemplateFromPath reads and decrypts a template file from a specific
// path, as the key type its filename names.
//
// The directory is deliberately not part of the identity: an installed
// template and the same template under deleted/ are the same object, and
// generations copy templates between namespaces without re-encrypting them.
func LoadTemplateFromPath(path string, kr *crypto.Keyring) ([]byte, error) {
	ctx, err := TemplateContextForFile(path)
	if err != nil {
		return nil, err
	}
	return keys.ReadAndDecryptFile(path, kr, ctx, "template file")
}

// TemplateContextForFile recovers a template's object context from its
// canonical filename, which is the key type plus the template extension.
func TemplateContextForFile(path string) (crypto.ObjectContext, error) {
	name := filepath.Base(path)
	keyType := strings.TrimSuffix(name, TemplateFileExtension)
	if keyType == name || keyType == "" {
		return crypto.ObjectContext{}, fmt.Errorf(
			"%q is not a canonical key-type template filename", name,
		)
	}
	return crypto.KeyTypeTemplateContext(normalizeKeyType(keyType)), nil
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

func LoadAllTemplatesForPaths(paths storepaths.Paths, identityID string, templateType TemplateType, kr *crypto.Keyring) (map[string][]byte, error) {
	files, err := ScanTemplateDirectoryForPaths(paths, identityID, templateType)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]byte)
	for _, file := range files {
		data, err := LoadTemplateFromPath(file.FilePath, kr)
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
