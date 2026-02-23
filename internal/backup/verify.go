// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package backup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/util"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"
)

// VerifyResult contains the result of verifying a single key file
type VerifyResult struct {
	Address  string
	FileName string
	Size     int64
	Valid    bool
	Error    string
	KeyType  string // Only set for deep verification
}

// VerifyReport contains the results of verifying a backup directory
type VerifyReport struct {
	BackupDir   string
	TotalFiles  int
	ValidFiles  int
	FailedFiles int
	Results     []VerifyResult
}

// VerifyBackup performs basic validation of all .apb files in a backup directory
// Does not require passphrase - only checks file format
func VerifyBackup(backupDir string) (*VerifyReport, error) {
	// Scan for .apb files
	addresses, err := ScanBackupFiles(backupDir)
	if err != nil {
		return nil, err
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("no .apb files found in %s", backupDir)
	}

	report := &VerifyReport{
		BackupDir: backupDir,
		Results:   make([]VerifyResult, 0, len(addresses)),
	}

	for _, address := range addresses {
		result := verifyFileBasic(backupDir, address)
		report.Results = append(report.Results, result)

		if result.Valid {
			report.ValidFiles++
		} else {
			report.FailedFiles++
		}
	}

	report.TotalFiles = len(report.Results)
	return report, nil
}

// verifyFileBasic performs basic validation without decryption
func verifyFileBasic(backupDir, address string) VerifyResult {
	result := VerifyResult{
		Address:  address,
		FileName: address + ".apb",
	}

	filePath := filepath.Join(backupDir, result.FileName)

	// Check file exists and get size
	info, err := os.Stat(filePath)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("file not found: %v", err)
		return result
	}
	result.Size = info.Size()

	// Check file is not empty
	if result.Size == 0 {
		result.Valid = false
		result.Error = "file is empty"
		return result
	}

	// Try to read and parse as JSON
	data, err := os.ReadFile(filePath)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("failed to read file: %v", err)
		return result
	}

	// Check if it's encrypted or plain JSON
	if crypto.IsEncrypted(data) {
		// It's encrypted - check EncryptedData structure is valid
		var encrypted crypto.EncryptedData
		if err := json.Unmarshal(data, &encrypted); err != nil {
			result.Valid = false
			result.Error = "invalid encrypted data format"
			return result
		}
		// Check required fields by envelope version
		switch encrypted.EnvelopeVersion {
		case 2:
			// Standalone: must have salt, nonce, ciphertext
			if encrypted.Salt == "" || encrypted.Nonce == "" || encrypted.Ciphertext == "" {
				result.Valid = false
				result.Error = "missing required encryption fields (standalone v2)"
				return result
			}
		case 1:
			// Master key: nonce and ciphertext required, salt empty
			if encrypted.Nonce == "" || encrypted.Ciphertext == "" {
				result.Valid = false
				result.Error = "missing required encryption fields (master key v1)"
				return result
			}
		default:
			result.Valid = false
			result.Error = fmt.Sprintf("unsupported envelope_version: %d", encrypted.EnvelopeVersion)
			return result
		}
	} else {
		// It's plain JSON - validate KeyPair structure
		var keyPair utilkeys.KeyPair
		if err := json.Unmarshal(data, &keyPair); err != nil {
			result.Valid = false
			result.Error = "invalid JSON format"
			return result
		}
		// Check required fields exist
		if keyPair.KeyType == "" || keyPair.PublicKeyHex == "" || keyPair.PrivateKeyHex == "" {
			result.Valid = false
			result.Error = "missing required key fields"
			return result
		}
	}

	result.Valid = true
	return result
}

// DeepVerifyBackup performs deep validation by decrypting and validating all key files.
// backupDir is the backup root (containing keys/ subdirectory).
// Requires the export passphrase used to create the standalone backup.
func DeepVerifyBackup(backupDir, passphrase string) (*VerifyReport, error) {
	// Scan for .apb files in apb/ subdirectory
	keysDir := filepath.Join(backupDir, "apb")
	addresses, err := ScanBackupFiles(keysDir)
	if err != nil {
		return nil, err
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("no .apb files found in %s", keysDir)
	}

	report := &VerifyReport{
		BackupDir: backupDir,
		Results:   make([]VerifyResult, 0, len(addresses)),
	}

	for _, address := range addresses {
		result := verifyFileDeep(keysDir, address, []byte(passphrase))
		report.Results = append(report.Results, result)

		if result.Valid {
			report.ValidFiles++
		} else {
			report.FailedFiles++
		}
	}

	report.TotalFiles = len(report.Results)
	return report, nil
}

// verifyFileDeep performs deep validation by decrypting and parsing the key
func verifyFileDeep(backupDir, address string, passphrase []byte) VerifyResult {
	result := VerifyResult{
		Address:  address,
		FileName: address + ".apb",
	}

	filePath := filepath.Join(backupDir, result.FileName)

	// Get file size
	info, err := os.Stat(filePath)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("file not found: %v", err)
		return result
	}
	result.Size = info.Size()

	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("failed to read file: %v", err)
		return result
	}

	// Decrypt if encrypted (using standalone decryption)
	var decryptedData []byte
	if crypto.IsEncrypted(data) {
		decrypted, err := crypto.DecryptStandalone(data, passphrase)
		if err != nil {
			result.Valid = false
			result.Error = fmt.Sprintf("decryption failed: %v", err)
			return result
		}
		decryptedData = decrypted
	} else {
		decryptedData = data
	}

	// Extract key JSON from backup payload (may be a bundle with embedded template)
	keyJSON, _, _, err := ParseBackup(decryptedData)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("failed to parse backup payload: %v", err)
		return result
	}

	// Parse KeyPair
	var keyPair utilkeys.KeyPair
	if err := json.Unmarshal(keyJSON, &keyPair); err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("invalid key format: %v", err)
		return result
	}

	// Validate required fields
	if keyPair.KeyType == "" {
		result.Valid = false
		result.Error = "missing key type"
		return result
	}
	if keyPair.PublicKeyHex == "" || keyPair.PrivateKeyHex == "" {
		result.Valid = false
		result.Error = "missing key data"
		return result
	}

	// Verify address matches filename (derive from public key)
	deriver, err := util.GetAddressDeriver(keyPair.KeyType)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("unsupported key type: %s", keyPair.KeyType)
		return result
	}

	derivedAddress, err := deriver.DeriveAddress(keyPair.PublicKeyHex, keyPair.Params)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("failed to derive address: %v", err)
		return result
	}

	if derivedAddress != address {
		result.Valid = false
		result.Error = fmt.Sprintf("address mismatch: filename=%s, derived=%s", address, derivedAddress)
		return result
	}

	result.Valid = true
	result.KeyType = keyPair.KeyType
	return result
}
