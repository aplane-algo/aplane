// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keyclass"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/witness"
)

// VerifyResult contains the result of verifying one complete credential.
type VerifyResult struct {
	Address  string
	FileName string
	Size     int64
	Valid    bool
	Error    string
	KeyType  string
}

type VerifyReport struct {
	BackupDir   string
	TotalFiles  int
	ValidFiles  int
	FailedFiles int
	Results     []VerifyResult
}

func DeepVerifyBackup(backupDir, passphrase string) (*VerifyReport, error) {
	return DeepVerifyBackupBytes(backupDir, []byte(passphrase))
}

// DeepVerifyBackupBytes authenticates the exact archive inventory and checks
// that every member is a self-contained, canonical credential supported by
// the source node role. Verification has no network or template dependency.
func DeepVerifyBackupBytes(backupDir string, passphrase []byte) (*VerifyReport, error) {
	manifest, err := OpenSealedManifest(backupDir, passphrase)
	if err != nil {
		return nil, err
	}
	role, err := noderole.ParseRole(manifest.SourceNodeRole)
	if err != nil {
		return nil, fmt.Errorf("invalid backup source node role: %w", err)
	}
	keysDir := filepath.Join(backupDir, "apb")
	addresses, err := ScanBackupFiles(keysDir)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no .apb files found in %s", keysDir)
	}
	report := &VerifyReport{BackupDir: backupDir, Results: make([]VerifyResult, 0, len(addresses))}
	for _, address := range addresses {
		result := verifyFileDeep(keysDir, address, passphrase, role)
		report.Results = append(report.Results, result)
		if result.Valid {
			report.ValidFiles++
		} else {
			report.FailedFiles++
		}
	}
	policyKeys, err := scanBackupPolicies(keysDir)
	if err != nil {
		return nil, err
	}
	for _, key := range policyKeys {
		result := verifyPolicyDeep(keysDir, key, passphrase, report.Results)
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

// verifyPolicyDeep checks one archived policy: it must belong to a cosigner
// credential in the archive and decode as that key's v1 document.
func verifyPolicyDeep(keysDir, key string, passphrase []byte, credentials []VerifyResult) VerifyResult {
	result := VerifyResult{Address: key, FileName: backupPoliciesDir + "/" + key + ".apb", KeyType: "policy"}
	hasCredential := false
	for _, c := range credentials {
		if c.Address == key && c.Valid && witness.IsKeyType(c.KeyType) {
			hasCredential = true
		}
	}
	if !hasCredential {
		result.Error = "policy has no cosigner credential in the archive"
		return result
	}
	if _, err := readBackupPolicy(keysDir, key, passphrase); err != nil {
		result.Error = err.Error()
		return result
	}
	result.Valid = true
	return result
}

func verifyFileDeep(backupDir, address string, passphrase []byte, role noderole.Role) VerifyResult {
	result := VerifyResult{Address: address, FileName: address + ".apb"}
	filePath := filepath.Join(backupDir, result.FileName)
	info, err := os.Stat(filePath)
	if err != nil {
		result.Error = fmt.Sprintf("file not found: %v", err)
		return result
	}
	result.Size = info.Size()
	data, _, err := fsutil.ReadRegularFileLimited(filePath, crypto.MaxStandaloneEnvelopeBytes)
	if err != nil {
		result.Error = fmt.Sprintf("failed to read file: %v", err)
		return result
	}
	if !crypto.IsEncrypted(data) {
		result.Error = "backup file must be encrypted"
		return result
	}
	var envelope struct {
		EnvelopeVersion int `json:"envelope_version"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		result.Error = fmt.Sprintf("invalid backup envelope: %v", err)
		return result
	}
	if envelope.EnvelopeVersion != 2 {
		result.Error = fmt.Sprintf("unsupported backup envelope_version %d", envelope.EnvelopeVersion)
		return result
	}
	decrypted, err := crypto.DecryptStandalone(data, passphrase)
	if err != nil {
		result.Error = fmt.Sprintf("decryption failed: %v", err)
		return result
	}
	defer crypto.ZeroBytes(decrypted)
	keyJSON, err := ParseBackup(decrypted)
	if err != nil {
		result.Error = fmt.Sprintf("failed to parse backup payload: %v", err)
		return result
	}
	payload, err := keys.ParsePayload(keyJSON)
	if err != nil {
		result.Error = fmt.Sprintf("invalid key format: %v", err)
		return result
	}
	defer payload.ZeroSecrets()
	selector, err := payload.Selector()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if selector != address {
		result.Error = fmt.Sprintf("address mismatch: filename=%s, derived=%s", address, selector)
		return result
	}
	if err := keyclass.ValidateKeyTypeAllowedForNodeRole(role, payload.KeyType); err != nil {
		result.Error = fmt.Sprintf("role-forbidden: %v", err)
		return result
	}
	canonical, err := keys.MarshalPayload(payload)
	if err != nil {
		result.Error = fmt.Sprintf("canonicalize credential: %v", err)
		return result
	}
	entry := CredentialEntry{Selector: selector, Category: payload.Category, KeyType: payload.KeyType, KeyJSON: canonical}
	defer entry.ZeroSecrets()
	if err := validateCredentialRuntimeSupport(&entry); err != nil {
		result.Error = err.Error()
		return result
	}
	result.Valid = true
	result.KeyType = payload.KeyType
	return result
}
