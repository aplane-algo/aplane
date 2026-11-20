// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/noderole"
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
		result := verifyPolicyDeep(keysDir, key, passphrase, role, report.Results)
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

// verifyPolicyDeep checks one archived policy: it must belong to a
// credential in the archive and decode as that key's v1 document for role.
func verifyPolicyDeep(keysDir, key string, passphrase []byte, role noderole.Role, credentials []VerifyResult) VerifyResult {
	result := VerifyResult{Address: key, FileName: backupPoliciesDir + "/" + key + ".apb", KeyType: "policy"}
	hasCredential := false
	for _, c := range credentials {
		if c.Address == key && c.Valid {
			hasCredential = true
		}
	}
	if !hasCredential {
		result.Error = "policy has no credential in the archive"
		return result
	}
	if _, err := readBackupPolicy(keysDir, key, passphrase, role); err != nil {
		result.Error = err.Error()
		return result
	}
	result.Valid = true
	return result
}

// verifyFileDeep admits one archived credential with restore's loader, so a
// credential that verifies is one restore accepts.
func verifyFileDeep(keysDir, address string, passphrase []byte, role noderole.Role) VerifyResult {
	result := VerifyResult{Address: address, FileName: address + ".apb"}
	if info, err := os.Stat(filepath.Join(keysDir, result.FileName)); err == nil {
		result.Size = info.Size()
	}
	entry, err := loadCredentialEntry(keysDir, address, passphrase, role)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	entry.ZeroSecrets()
	result.Valid = true
	result.KeyType = entry.KeyType()
	return result
}
