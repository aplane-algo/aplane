// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package templatestore owns the encrypted YAML template document format and
// primitive save, read, scan, and archive operations for the product store.
// Feature-level mutation must route through templatelibrary; callers of these
// primitives are responsible for already holding the appropriate live
// store-mutation lock or operating on an unpublished staged generation.
//
// A template's specification, which the LogicSig template packages read, is
// internal/templatespec: they need no store. Templates are stored as encrypted
// YAML files with the .template extension.
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
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatespec"
)

// TemplateFileExtension is the suffix every key-type template file carries.
// The name before it is the key type, which is the template's logical
// identity.
const TemplateFileExtension = ".template"

func GetTemplateFilePathForPaths(paths storepaths.Paths, keyType string) (string, error) {
	active, err := genstore.Resolve(paths)
	if err != nil {
		return "", err
	}
	return GetTemplateFilePathActive(active, keyType), nil
}

// GetTemplateFilePathActive is GetTemplateFilePathForPaths against resolved
// authenticated active-generation paths.
func GetTemplateFilePathActive(active storepaths.GenPaths, keyType string) string {
	return active.KeyTypeTemplate(normalizeKeyType(keyType))
}

// SaveTemplateActive writes an encrypted template against resolved active-store
// paths.
func SaveTemplateActive(active storepaths.GenPaths, yamlData []byte, keyType string, templateType templatespec.TemplateType, kr *crypto.Keyring) (string, error) {
	keyType = normalizeKeyType(keyType)
	if _, ok := SourceForTemplateType(templateType); !ok {
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
	outputPath := GetTemplateFilePathActive(active, keyType)
	// Durable, never in-place (docs/ARCH_STORE.md, "Filesystem primitives").
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

func TemplateExistsForPaths(paths storepaths.Paths, keyType string, templateType templatespec.TemplateType) bool {
	active, err := genstore.Resolve(paths)
	if err != nil {
		return false
	}
	return TemplateExistsActive(active, keyType, templateType)
}

// TemplateExistsActive is TemplateExistsForPaths against resolved
// active-store paths.
func TemplateExistsActive(active storepaths.GenPaths, keyType string, templateType templatespec.TemplateType) bool {
	source, sourceOK := SourceForTemplateType(templateType)
	if !sourceOK {
		return false
	}
	rec, ok, err := keytypestate.GetActive(active, keyType)
	if err != nil || !ok || rec.Source != source {
		return false
	}
	path := GetTemplateFilePathActive(active, keyType)
	_, err = os.Stat(path)
	return err == nil
}

// ScanTemplateFiles scans a template directory and returns file info for each .template file.
type TemplateFileInfo struct {
	KeyType  string // Derived from filename (without .template)
	FilePath string // Full path to the file
}

func ScanTemplateDirectoryForPaths(paths storepaths.Paths, templateType templatespec.TemplateType) ([]TemplateFileInfo, error) {
	source, ok := SourceForTemplateType(templateType)
	if !ok {
		return nil, fmt.Errorf("unsupported template_type %q", templateType)
	}
	records, err := keytypestate.List(paths)
	if err != nil {
		return nil, err
	}

	var files []TemplateFileInfo
	for _, rec := range records {
		if rec.Source != source {
			continue
		}
		path, err := GetTemplateFilePathForPaths(paths, rec.KeyType)
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

// SourceForTemplateType is the key type state source a template of
// templateType is recorded under.
func SourceForTemplateType(templateType templatespec.TemplateType) (keytypestate.Source, bool) {
	switch templateType {
	case templatespec.TemplateTypeGeneric:
		return keytypestate.SourceYAMLGeneric, true
	case templatespec.TemplateTypeComposed:
		return keytypestate.SourceYAMLComposed, true
	default:
		return "", false
	}
}

// TemplateTypeForSource is the template type a key type state source records,
// the inverse of SourceForTemplateType.
func TemplateTypeForSource(source keytypestate.Source) (templatespec.TemplateType, bool) {
	switch source {
	case keytypestate.SourceYAMLGeneric:
		return templatespec.TemplateTypeGeneric, true
	case keytypestate.SourceYAMLComposed:
		return templatespec.TemplateTypeComposed, true
	default:
		return "", false
	}
}

func normalizeKeyType(keyType string) string {
	return strings.ToLower(strings.TrimSpace(keyType))
}
