// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
)

func exportManagedCredential(destDir string, source keys.ManagedCredentialFile, kr *crypto.Keyring, exportPassphrase []byte) error {
	destFile := filepath.Join(destDir, source.Selector+".apb")

	// Read source key file
	data, err := os.ReadFile(source.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("managed credential file not found: %s", source.Name)
		}
		return fmt.Errorf("failed to read managed credential: %w", err)
	}

	ctx, err := source.Context()
	if err != nil {
		return err
	}
	plaintext, err := kr.Open(data, ctx)
	if err != nil {
		return fmt.Errorf("failed to decrypt key: %w", err)
	}
	defer crypto.ZeroBytes(plaintext)

	// The portable authority is the complete managed credential payload. The
	// destination owns templates and key-generation configuration.
	payload, err := buildExportPayload(source, plaintext)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(payload)

	// Re-encrypt with standalone encryption
	standaloneData, err := crypto.EncryptStandalone(payload, exportPassphrase)
	if err != nil {
		return fmt.Errorf("failed to encrypt for export: %w", err)
	}

	// Write to destination
	if err := os.WriteFile(destFile, standaloneData, 0600); err != nil {
		return fmt.Errorf("failed to write export file: %w", err)
	}
	return nil
}

// buildExportPayload checks the decrypted credential against its source
// filename and returns a canonical credential-only plaintext for export.
func buildExportPayload(source keys.ManagedCredentialFile, plaintext []byte) ([]byte, error) {
	payload, err := keys.ParsePayload(plaintext)
	if err != nil {
		return nil, err
	}
	defer payload.ZeroSecrets()
	selector, err := payload.Selector()
	if err != nil {
		return nil, err
	}
	if err := keys.ValidateManagedCredentialFilename(source.Name, selector, payload.Category); err != nil {
		return nil, err
	}
	canonical, err := keys.MarshalPayload(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to build export payload for %s: %w", source.Selector, err)
	}
	return canonical, nil
}

// exportCredentials writes the standalone backup of each selected managed
// credential in srcDir to destDir, or of every one when selected is empty,
// from one scan of srcDir. It returns the exported selectors: in address
// order for a complete backup, in request order for a selection. A selector
// held in both filename classes is refused only when it would be exported.
//
// The backup is complete or fails: silently omitting one damaged authority
// would make the archive's sealed inventory look complete even though the
// source store was not fully represented.
func exportCredentials(srcDir, destDir string, selected []string, kr *crypto.Keyring, exportPassphrase []byte) ([]string, error) {
	files, err := keys.ScanManagedCredentialFiles(srcDir)
	if err != nil {
		return nil, err
	}
	bySelector := make(map[string][]keys.ManagedCredentialFile, len(files))
	for _, file := range files {
		bySelector[file.Selector] = append(bySelector[file.Selector], file)
	}
	if len(selected) == 0 {
		if len(files) == 0 {
			return nil, fmt.Errorf("no managed credential files found in %s", srcDir)
		}
		selected = slices.Sorted(maps.Keys(bySelector))
	}
	sources := make([]keys.ManagedCredentialFile, 0, len(selected))
	for _, selector := range selected {
		switch matches := bySelector[selector]; len(matches) {
		case 0:
			return nil, fmt.Errorf("managed credential not found: %s", selector)
		case 1:
			sources = append(sources, matches[0])
		default:
			return nil, fmt.Errorf("ambiguous managed credential %s: %s and %s", selector, matches[0].Name, matches[1].Name)
		}
	}

	if err := os.MkdirAll(destDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create backup keys directory: %w", err)
	}
	for _, source := range sources {
		if err := exportManagedCredential(destDir, source, kr, exportPassphrase); err != nil {
			return nil, fmt.Errorf("failed to export %s: %w", source.Selector, err)
		}
	}
	return selected, nil
}
