// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
)

// ParseBackup returns the complete canonical managed credential payload.
// Backup bundles were an internal pre-release format and are deliberately not
// accepted by the first supported credential-backup contract.
func ParseBackup(decryptedJSON []byte) ([]byte, error) {
	var probe struct {
		BackupBundle int `json:"backup_bundle"`
	}
	if err := json.Unmarshal(decryptedJSON, &probe); err != nil {
		return nil, fmt.Errorf("failed to parse backup data: %w", err)
	}

	if probe.BackupBundle != 0 {
		return nil, fmt.Errorf(
			"unsupported internal backup bundle format; create a new credential backup with this release",
		)
	}
	parsed, err := keys.ParsePayload(decryptedJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse backup credential: %w", err)
	}
	parsed.ZeroSecrets()
	return decryptedJSON, nil
}

// ExportKey exports a single key file from the keystore to a standalone backup.
// It decrypts the key with the store's keyring, then re-encrypts it with the
// export passphrase using standalone encryption (envelope_version 2).
func ExportKey(srcDir, destDir, address string, kr *crypto.Keyring, exportPassphrase []byte) error {
	source, err := resolveManagedCredentialFile(srcDir, address)
	if err != nil {
		return err
	}
	return exportManagedCredential(destDir, source, kr, exportPassphrase)
}

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
	if err := validateExportSource(source, plaintext); err != nil {
		return err
	}

	// The portable authority is the complete managed credential payload. The
	// destination owns templates and key-generation configuration.
	payload, err := buildExportPayload(plaintext)
	if err != nil {
		return fmt.Errorf("failed to build export payload for %s: %w", source.Selector, err)
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

func resolveManagedCredentialFile(srcDir, selector string) (keys.ManagedCredentialFile, error) {
	files, err := keys.ScanManagedCredentialFiles(srcDir)
	if err != nil {
		return keys.ManagedCredentialFile{}, err
	}
	var matches []keys.ManagedCredentialFile
	for _, file := range files {
		if file.Selector == selector {
			matches = append(matches, file)
		}
	}
	switch len(matches) {
	case 0:
		return keys.ManagedCredentialFile{}, fmt.Errorf("managed credential not found: %s", selector)
	case 1:
		return matches[0], nil
	default:
		return keys.ManagedCredentialFile{}, fmt.Errorf("ambiguous managed credential %s: both filename classes are present", selector)
	}
}

func validateExportSource(source keys.ManagedCredentialFile, plaintext []byte) error {
	payload, err := keys.ParsePayload(plaintext)
	if err != nil {
		return err
	}
	defer payload.ZeroSecrets()
	selector, err := payload.Selector()
	if err != nil {
		return err
	}
	if err := keys.ValidateManagedCredentialFilename(source.Name, selector, payload.Category); err != nil {
		return err
	}
	return nil
}

// buildExportPayload returns a canonical credential-only plaintext for export.
func buildExportPayload(keyJSON []byte) ([]byte, error) {
	payload, err := keys.ParsePayload(keyJSON)
	if err != nil {
		return nil, err
	}
	defer payload.ZeroSecrets()
	canonical, err := keys.MarshalPayload(payload)
	if err != nil {
		return nil, err
	}
	return canonical, nil
}

// ExportAllKeys exports all managed credential files from the keystore to a standalone backup directory.
// Each file is decrypted with the store's keyring and re-encrypted with the export
// passphrase using standalone encryption (envelope_version 2).
// No .keystore file is written — each backup file is self-contained.
//
// The backup is complete or fails: silently omitting damaged authority would
// make the sealed archive inventory look complete when it is not.
func ExportAllKeys(srcDir, destDir string, kr *crypto.Keyring, exportPassphrase []byte) error {
	managedFiles, err := keys.ScanManagedCredentialFiles(srcDir)
	if err != nil {
		return err
	}

	if len(managedFiles) == 0 {
		return fmt.Errorf("no managed credential files found in %s", srcDir)
	}
	seenSelectors := make(map[string]string, len(managedFiles))
	for _, file := range managedFiles {
		if previous, ok := seenSelectors[file.Selector]; ok {
			return fmt.Errorf("ambiguous managed credential %s: %s and %s", file.Selector, previous, file.Name)
		}
		seenSelectors[file.Selector] = file.Name
	}

	// Create apb subdirectory in backup
	keysDestDir := filepath.Join(destDir, "apb")
	if err := os.MkdirAll(keysDestDir, 0750); err != nil {
		return fmt.Errorf("failed to create backup keys directory: %w", err)
	}

	// Export each credential. A complete backup is fail-closed: silently
	// omitting one damaged authority would make the archive's sealed inventory
	// look complete even though the source store was not fully represented.
	for _, managedFile := range managedFiles {
		if err := exportManagedCredential(keysDestDir, managedFile, kr, exportPassphrase); err != nil {
			return fmt.Errorf("failed to export %s: %w", managedFile.Selector, err)
		}
	}
	return nil
}
