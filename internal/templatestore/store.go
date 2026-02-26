// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package templatestore provides common utilities for storing and loading
// encrypted YAML template files in the keystore.
//
// This package is used by both:
//   - multitemplate: Generic LogicSig templates (TEAL-only)
//   - falcon1024template: Falcon-1024 DSA composition templates
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
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"
)

// BaseTemplateSpec contains fields common to all template types.
// Specific template systems embed this and add their own fields.
type BaseTemplateSpec struct {
	SchemaVersion int    `yaml:"schema_version"`
	TemplateType  string `yaml:"template_type"` // "falcon" or "generic" (optional, aids detection)
	Family        string `yaml:"family"`
	Version       int    `yaml:"version"`
	DisplayName   string `yaml:"display_name"`
	Description   string `yaml:"description"`
	DisplayColor  string `yaml:"display_color"`
}

// KeyType returns the computed key type (family-vN).
func (s *BaseTemplateSpec) KeyType() string {
	return fmt.Sprintf("%s-v%d", s.Family, s.Version)
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
	if s.Family == "" {
		return fmt.Errorf("family is required")
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
	// TemplateTypeGeneric is for generic LogicSig templates (multitemplate).
	TemplateTypeGeneric TemplateType = "generic"
	// TemplateTypeFalcon is for Falcon-1024 DSA composition templates.
	TemplateTypeFalcon TemplateType = "falcon"
)

// GetTemplateDir returns the directory for a given template type.
func GetTemplateDir(templateType TemplateType) string {
	switch templateType {
	case TemplateTypeFalcon:
		return utilkeys.FalconTemplatesDir()
	default:
		return utilkeys.TemplatesDir()
	}
}

// GetTemplateFilePath returns the full path for a template file.
func GetTemplateFilePath(keyType string, templateType TemplateType) string {
	return filepath.Join(GetTemplateDir(templateType), keyType+".template")
}

// SaveTemplate encrypts and saves a template YAML to the keystore.
func SaveTemplate(yamlData []byte, keyType string, templateType TemplateType, masterKey []byte) (string, error) {
	dir := GetTemplateDir(templateType)

	// Ensure directory exists
	if err := fsutil.MkdirAll(dir); err != nil {
		return "", fmt.Errorf("failed to create templates directory: %w", err)
	}

	// Encrypt with master key
	encrypted, err := crypto.EncryptWithMasterKey(yamlData, masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt template: %w", err)
	}

	// Write the file
	outputPath := GetTemplateFilePath(keyType, templateType)
	if err := fsutil.WriteFile(outputPath, encrypted); err != nil {
		return "", fmt.Errorf("failed to write template file: %w", err)
	}

	return outputPath, nil
}

// LoadTemplateFromPath reads and decrypts a template file from a specific path.
func LoadTemplateFromPath(path string, masterKey []byte) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read template file: %w", err)
	}

	// Check if encrypted
	if !crypto.IsEncrypted(data) {
		return data, nil
	}

	if len(masterKey) == 0 {
		return nil, fmt.Errorf("template file is encrypted but no master key provided")
	}

	decrypted, err := crypto.DecryptWithMasterKey(data, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt template file: %w", err)
	}

	return decrypted, nil
}

// TemplateExists checks if a template file already exists.
func TemplateExists(keyType string, templateType TemplateType) bool {
	path := GetTemplateFilePath(keyType, templateType)
	_, err := os.Stat(path)
	return err == nil
}

// ScanTemplateFiles scans a template directory and returns file info for each .template file.
type TemplateFileInfo struct {
	KeyType  string // Derived from filename (without .template)
	FilePath string // Full path to the file
}

// ScanTemplateDirectory scans the template directory and returns info about each template file.
func ScanTemplateDirectory(templateType TemplateType) ([]TemplateFileInfo, error) {
	dir := GetTemplateDir(templateType)

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // Directory doesn't exist yet, that's OK
		}
		return nil, fmt.Errorf("failed to read templates directory: %w", err)
	}

	var files []TemplateFileInfo
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".template") {
			continue
		}

		keyType := strings.TrimSuffix(entry.Name(), ".template")
		files = append(files, TemplateFileInfo{
			KeyType:  keyType,
			FilePath: filepath.Join(dir, entry.Name()),
		})
	}

	return files, nil
}

// LoadAllTemplates loads and decrypts all templates from a directory.
// Returns a map of keyType -> decrypted YAML data.
// Errors for individual files are logged but don't stop processing.
func LoadAllTemplates(templateType TemplateType, masterKey []byte) (map[string][]byte, error) {
	files, err := ScanTemplateDirectory(templateType)
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
