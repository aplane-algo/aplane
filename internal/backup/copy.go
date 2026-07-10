// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"
)

const (
	BackupBundleSentinel              = 1
	CurrentBackupBundlePayloadVersion = 1
)

// BackupBundle wraps a key and its associated template into a single JSON payload.
// When backup_bundle is present, the decrypted content is a bundle; when absent,
// the content is a plain canonical key payload.
type BackupBundle struct {
	BackupBundle   int             `json:"backup_bundle"`
	PayloadVersion int             `json:"payload_version,omitempty"`
	Key            json.RawMessage `json:"key"`
	TemplateYAML   string          `json:"template_yaml"`
	TemplateType   string          `json:"template_type"`
}

// ParseBackup inspects decrypted backup JSON and extracts the key payload and
// optional template. If the data is a BackupBundle, it returns the embedded key
// JSON and template YAML separately. If it's a plain canonical key payload, it
// returns the data as-is with no template.
func ParseBackup(decryptedJSON []byte) (keyJSON []byte, templateYAML []byte, templateType string, err error) {
	// Quick check: does the JSON contain backup_bundle?
	var probe struct {
		BackupBundle int `json:"backup_bundle"`
	}
	if err := json.Unmarshal(decryptedJSON, &probe); err != nil {
		return nil, nil, "", fmt.Errorf("failed to parse backup data: %w", err)
	}

	if probe.BackupBundle == 0 {
		// Plain canonical key payload — return as-is
		return decryptedJSON, nil, "", nil
	}
	if probe.BackupBundle != BackupBundleSentinel {
		return nil, nil, "", fmt.Errorf("unsupported backup_bundle sentinel: %d", probe.BackupBundle)
	}

	// It's a bundle — extract fields
	var bundle BackupBundle
	if err := json.Unmarshal(decryptedJSON, &bundle); err != nil {
		return nil, nil, "", fmt.Errorf("failed to parse backup bundle: %w", err)
	}

	if len(bundle.Key) == 0 {
		return nil, nil, "", fmt.Errorf("backup bundle has empty key field")
	}
	var versionProbe struct {
		PayloadVersion *int `json:"payload_version"`
	}
	if err := json.Unmarshal(decryptedJSON, &versionProbe); err != nil {
		return nil, nil, "", fmt.Errorf("failed to parse backup bundle payload version: %w", err)
	}
	payloadVersion := CurrentBackupBundlePayloadVersion
	if versionProbe.PayloadVersion != nil {
		payloadVersion = *versionProbe.PayloadVersion
	}
	if payloadVersion != CurrentBackupBundlePayloadVersion {
		return nil, nil, "", fmt.Errorf("unsupported backup bundle payload_version: %d", payloadVersion)
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
// If the key is template-backed, the template YAML is bundled into the same
// encrypted payload (no separate .template file) when an installed
// identity-local template is available.
// Returns the SHA256 checksum of the written key file and its size.
func ExportKey(paths storepaths.Paths, identityID, srcDir, destDir, address string, masterKey, exportPassphrase []byte) (string, int64, error) {
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
	payload, err := buildExportPayload(paths, identityID, plaintext, masterKey)
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
// If the key is template-backed, it builds a BackupBundle JSON containing both
// the key and the template YAML. Otherwise it returns the key JSON as-is.
func buildExportPayload(paths storepaths.Paths, identityID string, keyJSON, masterKey []byte) ([]byte, error) {
	// Parse key to get key type
	payload, err := keys.ParsePayload(keyJSON)
	if err != nil {
		return nil, err
	}
	defer payload.ZeroSecrets()

	templateType, templatePlain, err := loadTemplateForExport(paths, identityID, payload.KeyType, masterKey)
	if err != nil {
		return nil, err
	}
	if len(templatePlain) == 0 {
		// No template — return key JSON as-is
		return append([]byte(nil), keyJSON...), nil
	}

	// Build bundle
	bundle := BackupBundle{
		BackupBundle:   BackupBundleSentinel,
		PayloadVersion: CurrentBackupBundlePayloadVersion,
		Key:            json.RawMessage(keyJSON),
		TemplateYAML:   string(templatePlain),
		TemplateType:   string(templateType),
	}

	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal backup bundle: %w", err)
	}

	return bundleJSON, nil
}

// loadTemplateForExport returns the template YAML to bundle with a key export.
// Installed identity-local templates are exported when available.
func loadTemplateForExport(paths storepaths.Paths, identityID, keyType string, masterKey []byte) (templatestore.TemplateType, []byte, error) {
	templateType, templatePath := findKeystoreTemplate(paths, identityID, keyType)
	if templatePath != "" {
		templatePlain, err := templatestore.LoadTemplateFromPath(templatePath, masterKey)
		if err != nil {
			return "", nil, fmt.Errorf("failed to read template: %w", err)
		}
		return templateType, templatePlain, nil
	}

	return "", nil, nil
}

// findKeystoreTemplate returns the template type and path if a keystore template
// exists for the given key type. Returns empty if the key type is built-in or
// has no associated template.
func findKeystoreTemplate(paths storepaths.Paths, identityID, keyType string) (templatestore.TemplateType, string) {
	for _, tt := range templatestore.ActiveTemplateTypes() {
		if templatestore.TemplateExistsForPaths(paths, identityID, keyType, tt) {
			return tt, templatestore.GetTemplateFilePathForPaths(paths, identityID, keyType, tt)
		}
	}
	return "", ""
}

// ExportAllKeys exports all .key files from the keystore to a standalone backup directory.
// Each file is decrypted with the store's master key and re-encrypted with the export
// passphrase using standalone encryption (envelope_version 2).
// No .keystore file is written — each backup file is self-contained.
//
// A key file that decrypts but fails canonical payload validation is skipped
// and reported in the returned skipped map (address -> reason) so a single
// damaged key cannot block backing up the remaining healthy keys. All other
// failures (read, decrypt, template, IO) still abort the export.
func ExportAllKeys(paths storepaths.Paths, identityID, srcDir, destDir string, masterKey, exportPassphrase []byte) (checksums, skipped map[string]string, err error) {
	// Scan source directory for .key files
	addresses, err := ScanKeyFiles(srcDir)
	if err != nil {
		return nil, nil, err
	}

	if len(addresses) == 0 {
		return nil, nil, fmt.Errorf("no .key files found in %s", srcDir)
	}

	// Create apb subdirectory in backup
	keysDestDir := filepath.Join(destDir, "apb")
	if err := os.MkdirAll(keysDestDir, 0750); err != nil {
		return nil, nil, fmt.Errorf("failed to create backup keys directory: %w", err)
	}

	// Export each key to keys/ subdirectory
	checksums = make(map[string]string)
	skipped = make(map[string]string)
	for _, address := range addresses {
		checksum, _, err := ExportKey(paths, identityID, srcDir, keysDestDir, address, masterKey, exportPassphrase)
		if err != nil {
			if isCanonicalPayloadRejection(err) {
				skipped[address] = err.Error()
				continue
			}
			return nil, nil, fmt.Errorf("failed to export %s: %w", address, err)
		}
		checksums[address] = checksum
	}

	if len(checksums) == 0 {
		return nil, nil, fmt.Errorf("no exportable keys: all %d key file(s) failed canonical payload validation", len(skipped))
	}

	return checksums, skipped, nil
}

// isCanonicalPayloadRejection reports whether an export failure means the
// decrypted key payload was rejected by the canonical codec, as opposed to an
// infrastructure failure (read, decrypt, template, IO) that must abort.
func isCanonicalPayloadRejection(err error) bool {
	return errors.Is(err, keys.ErrIncompatibleKeyFormat) ||
		errors.Is(err, keys.ErrMissingLogicSigSaltCounter)
}
