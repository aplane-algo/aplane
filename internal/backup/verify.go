// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/noderole"
)

// VerifiedCredential is one archived credential deep verify admitted.
type VerifiedCredential struct {
	Address string
	KeyType string
	// HasPolicy reports that the archive carries this key's own policy,
	// which verified with it.
	HasPolicy bool
}

// VerifyReport classifies every credential of an archive as a whole-archive
// restore into its source role would: admitted, or skipped with the reason.
type VerifyReport struct {
	BackupDir string
	Verified  []VerifiedCredential
	Skipped   []SkippedEntry
}

// DeepVerifyBackupBytes authenticates the exact archive inventory and admits
// every credential, with its archived policy, for the source node role, by
// the loader restore uses. An archive-level failure is an error; a credential
// restore would skip is listed in the report. Verification has no network or
// template dependency.
func DeepVerifyBackupBytes(backupDir string, passphrase []byte) (*VerifyReport, error) {
	archive, err := openArchive(backupDir, passphrase)
	if err != nil {
		return nil, err
	}
	role, err := noderole.ParseRole(archive.manifest.SourceNodeRole)
	if err != nil {
		return nil, fmt.Errorf("invalid backup source node role: %w", err)
	}
	report := &VerifyReport{BackupDir: backupDir, Verified: make([]VerifiedCredential, 0, len(archive.selectors))}
	report.Skipped, err = archive.admitEach(archive.selectors, passphrase, role, func(entry CredentialEntry) error {
		entry.ZeroSecrets()
		report.Verified = append(report.Verified, VerifiedCredential{
			Address: entry.Selector(), KeyType: entry.KeyType(), HasPolicy: entry.Policy != nil,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return report, nil
}

// Incomplete fails a report in which a whole-archive restore would skip a
// credential, naming how many and the first. It is nil when every credential
// verified.
func (r *VerifyReport) Incomplete() error {
	if len(r.Skipped) == 0 {
		return nil
	}
	first := r.Skipped[0]
	return fmt.Errorf("%d of %d credentials would be skipped by restore; first %s: %s",
		len(r.Skipped), len(r.Skipped)+len(r.Verified), first.Selector, first.Reason)
}
