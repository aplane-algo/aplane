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
	// SourceTokens names the sources the archive carries a token for under
	// this cosigner key, which verified with it; never a token.
	SourceTokens []string
}

// VerifyReport classifies every credential of an archive as a whole-archive
// restore into a node of one role would: admitted, or skipped with the
// reason.
type VerifyReport struct {
	BackupDir string
	Verified  []VerifiedCredential
	Skipped   []SkippedEntry
}

// DeepVerifyBackupBytes authenticates the exact archive inventory and admits
// every credential, with its archived policy and source tokens, for the
// source node role, by the loader restore uses. An archive-level failure is
// an error; a credential restore would skip is listed in the report.
// Verification has no network or template dependency.
func DeepVerifyBackupBytes(backupDir string, passphrase []byte) (*VerifyReport, error) {
	archive, err := openArchive(backupDir, passphrase)
	if err != nil {
		return nil, err
	}
	role, err := noderole.ParseRole(archive.manifest.SourceNodeRole)
	if err != nil {
		return nil, fmt.Errorf("invalid backup source node role: %w", err)
	}
	return archive.verify(backupDir, passphrase, role)
}

// VerifyImportedBackup admits every credential of an extracted archive for
// role, the role of the node importing it, by the loader restore uses. It
// refuses an archive in which nothing would restore on that node, as
// restore does: a backup of another node role in one line, and any other
// with a SkipRefusalError.
func VerifyImportedBackup(backupDir string, passphrase []byte, role noderole.Role) (*VerifyReport, error) {
	archive, err := openArchive(backupDir, passphrase)
	if err != nil {
		return nil, err
	}
	report, err := archive.verify(backupDir, passphrase, role)
	if err != nil {
		return nil, err
	}
	switch {
	case len(report.Verified) > 0:
		return report, nil
	case archive.manifest.SourceNodeRole != string(role):
		return nil, &OtherRoleError{Backup: archive.manifest.SourceNodeRole, Node: string(role)}
	default:
		return nil, &SkipRefusalError{Skipped: report.Skipped}
	}
}

// verify admits every credential of the archive for role.
func (a openedArchive) verify(backupDir string, passphrase []byte, role noderole.Role) (*VerifyReport, error) {
	report := &VerifyReport{BackupDir: backupDir, Verified: make([]VerifiedCredential, 0, len(a.selectors))}
	var err error
	report.Skipped, err = a.admitEach(a.selectors, passphrase, role, func(entry CredentialEntry) error {
		entry.ZeroSecrets()
		report.Verified = append(report.Verified, VerifiedCredential{
			Address: entry.Selector(), KeyType: entry.KeyType(), HasPolicy: entry.Policy != nil,
			SourceTokens: entry.SourceTokenNames(),
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

// OtherRoleError refuses an import of a backup of another node role, none of
// whose credentials this node can hold.
type OtherRoleError struct {
	Backup, Node string
}

func (e *OtherRoleError) Error() string {
	return fmt.Sprintf("this is a %s backup; a %s node cannot restore it", e.Backup, e.Node)
}
