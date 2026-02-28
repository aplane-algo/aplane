// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/templatestore"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"
)

// BackupBundle wraps a key and its associated template into a single JSON payload.
// When backup_bundle is present, the decrypted content is a bundle; when absent,
// the content is a plain KeyPair JSON (backward-compatible).
type BackupBundle struct {
	BackupBundle int             `json:"backup_bundle"`
	Key          json.RawMessage `json:"key"`
	TemplateYAML string          `json:"template_yaml"`
	TemplateType string          `json:"template_type"`
}

// ParseBackup inspects decrypted backup JSON and extracts the key payload and
// optional template. If the data is a BackupBundle, it returns the embedded key
// JSON and template YAML separately. If it's a plain KeyPair, it returns the
// data as-is with no template.
func ParseBackup(decryptedJSON []byte) (keyJSON []byte, templateYAML []byte, templateType string, err error) {
	// Quick check: does the JSON contain backup_bundle?
	var probe struct {
		BackupBundle int `json:"backup_bundle"`
	}
	if err := json.Unmarshal(decryptedJSON, &probe); err != nil {
		return nil, nil, "", fmt.Errorf("failed to parse backup data: %w", err)
	}

	if probe.BackupBundle == 0 {
		// Plain KeyPair — return as-is
		return decryptedJSON, nil, "", nil
	}

	// It's a bundle — extract fields
	var bundle BackupBundle
	if err := json.Unmarshal(decryptedJSON, &bundle); err != nil {
		return nil, nil, "", fmt.Errorf("failed to parse backup bundle: %w", err)
	}

	if len(bundle.Key) == 0 {
		return nil, nil, "", fmt.Errorf("backup bundle has empty key field")
	}

	var tmplYAML []byte
	if bundle.TemplateYAML != "" {
		tmplYAML = []byte(bundle.TemplateYAML)
	}

	return []byte(bundle.Key), tmplYAML, bundle.TemplateType, nil
}

// ExportKey exports a single key file from the keystore to a standalone backup.
// It decrypts the key with the store's master key, then re-encrypts it with the
// export passphrase using standalone encryption (envelope_version 2).
// If the key uses a keystore template, the template is bundled into the same
// encrypted payload (no separate .template file).
// Returns the SHA256 checksum of the written key file and its size.
func ExportKey(identityID, srcDir, destDir, address string, masterKey, exportPassphrase []byte) (string, int64, error) {
	srcFile := filepath.Join(srcDir, address+".key")
	destFile := filepath.Join(destDir, address+".apb")

	// Read source key file
	data, err := os.ReadFile(srcFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", 0, fmt.Errorf("key file not found: %s", address+".key")
		}
		return "", 0, fmt.Errorf("failed to read key file: %w", err)
	}

	// Decrypt with master key
	plaintext, err := crypto.DecryptWithMasterKey(data, masterKey)
	if err != nil {
		return "", 0, fmt.Errorf("failed to decrypt key: %w", err)
	}
	defer crypto.ZeroBytes(plaintext)

	// Determine what to encrypt: plain key or bundle with template
	payload, err := buildExportPayload(identityID, plaintext, masterKey)
	if err != nil {
		return "", 0, fmt.Errorf("failed to build export payload for %s: %w", address, err)
	}
	defer crypto.ZeroBytes(payload)

	// Re-encrypt with standalone encryption
	standaloneData, err := crypto.EncryptStandalone(payload, exportPassphrase)
	if err != nil {
		return "", 0, fmt.Errorf("failed to encrypt for export: %w", err)
	}

	// Write to destination
	if err := os.WriteFile(destFile, standaloneData, 0600); err != nil {
		return "", 0, fmt.Errorf("failed to write export file: %w", err)
	}

	// Compute checksum of written key file
	h := sha256.Sum256(standaloneData)
	checksum := hex.EncodeToString(h[:])

	return checksum, int64(len(standaloneData)), nil
}

// buildExportPayload returns the plaintext to encrypt for export.
// If the key has an associated template, it builds a BackupBundle JSON containing
// both the key and the template YAML. Otherwise it returns the key JSON as-is.
func buildExportPayload(identityID string, keyJSON, masterKey []byte) ([]byte, error) {
	// Parse key to get key type
	var kp utilkeys.KeyPair
	if err := json.Unmarshal(keyJSON, &kp); err != nil {
		// Can't parse — export key as-is
		return append([]byte(nil), keyJSON...), nil
	}

	// Check if this key type has a keystore template
	templateType, templatePath := findKeystoreTemplate(identityID, kp.KeyType)
	if templatePath == "" {
		// No template — return key JSON as-is
		return append([]byte(nil), keyJSON...), nil
	}

	// Decrypt template with master key
	templatePlain, err := templatestore.LoadTemplateFromPath(templatePath, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read template: %w", err)
	}

	// Build bundle
	bundle := BackupBundle{
		BackupBundle: 1,
		Key:          json.RawMessage(keyJSON),
		TemplateYAML: string(templatePlain),
		TemplateType: string(templateType),
	}

	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal backup bundle: %w", err)
	}

	return bundleJSON, nil
}

// findKeystoreTemplate returns the template type and path if a keystore template
// exists for the given key type. Returns empty if the key type is built-in or
// has no associated template.
func findKeystoreTemplate(identityID, keyType string) (templatestore.TemplateType, string) {
	for _, tt := range []templatestore.TemplateType{templatestore.TemplateTypeFalcon, templatestore.TemplateTypeGeneric} {
		if templatestore.TemplateExists(identityID, keyType, tt) {
			return tt, templatestore.GetTemplateFilePath(identityID, keyType, tt)
		}
	}
	return "", ""
}

// ExportAllKeys exports all .key files from the keystore to a standalone backup directory.
// Each file is decrypted with the store's master key and re-encrypted with the export
// passphrase using standalone encryption (envelope_version 2).
// No .keystore file is written — each backup file is self-contained.
func ExportAllKeys(identityID, srcDir, destDir string, masterKey, exportPassphrase []byte) (map[string]string, error) {
	// Scan source directory for .key files
	addresses, err := ScanKeyFiles(srcDir)
	if err != nil {
		return nil, err
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("no .key files found in %s", srcDir)
	}

	// Create apb subdirectory in backup
	keysDestDir := filepath.Join(destDir, "apb")
	if err := os.MkdirAll(keysDestDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create backup keys directory: %w", err)
	}

	// Export each key to keys/ subdirectory
	checksums := make(map[string]string)
	for _, address := range addresses {
		checksum, _, err := ExportKey(identityID, srcDir, keysDestDir, address, masterKey, exportPassphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to export %s: %w", address, err)
		}
		checksums[address] = checksum
	}

	return checksums, nil
}
