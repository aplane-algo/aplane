// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"

	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestProtocolRestoreBackupResultOmitsProcessLocalCommitState(t *testing.T) {
	msg := ProtocolRestoreBackupResultMessage("restore-1", adminproto.RestoreBackupResult{
		Success:         true,
		OperationID:     "operation-1",
		CommitUncertain: true,
	})

	wire, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if strings.Contains(string(wire), "commit_uncertain") {
		t.Fatalf("restore response exposed process-local commit state: %s", wire)
	}
}

// The signer's warnings reach the review on the wire, in order. A result without
// any carries no warnings field at all.
func TestProtocolPrepareGenerateResultCarriesWarnings(t *testing.T) {
	warnings := []string{
		"Fee limit 0 is too low to pay alone. A transaction on its own costs more: spend (at least 2000).",
		"a second note",
	}
	msg := ProtocolPrepareGenerateResultMessage("prepare-1", adminproto.PrepareGenerateKeyResult{
		Success: true, KeyType: "aplane.falcon1024.v1", Warnings: warnings,
		Bounded: &adminproto.PreparedBoundedProfile{Contract: "bounded2", SpendEffects: []string{"pay"}, MaxFee: new(uint64(0)), Rekey: "refused"},
	})
	if len(msg.Warnings) != 2 || msg.Warnings[0] != warnings[0] || msg.Warnings[1] != warnings[1] {
		t.Fatalf("Warnings = %q", msg.Warnings)
	}
	wire, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var decoded protocol.PrepareGenerateResultMessage
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !decoded.Success || len(decoded.Warnings) != 2 || decoded.Warnings[0] != warnings[0] || decoded.Warnings[1] != warnings[1] {
		t.Fatalf("decoded = %+v from %s", decoded, wire)
	}
	// A fee limit of zero is a value on the wire, not an absent one.
	if decoded.Bounded == nil || decoded.Bounded.MaxFee == nil || *decoded.Bounded.MaxFee != 0 || !strings.Contains(string(wire), `"max_fee":0`) {
		t.Fatalf("a zero fee limit was lost: %s", wire)
	}

	quiet, err := json.Marshal(ProtocolPrepareGenerateResultMessage("prepare-2", adminproto.PrepareGenerateKeyResult{Success: true, KeyType: "aplane.falcon1024.v1"}))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if strings.Contains(string(quiet), "warnings") {
		t.Fatalf("a result without warnings names them: %s", quiet)
	}
}

func TestProtocolKeyDetailsMessageIncludesPublicKey(t *testing.T) {
	msg := ProtocolKeyDetailsMessage("details-1", adminproto.GetKeyDetailsResult{
		Success:      true,
		Address:      "ADDR",
		KeyType:      "aplane.witness-falcon1024.v1",
		PublicKeyHex: "aabbccdd",
	})

	if msg.Type != protocol.MsgTypeKeyDetails || msg.ID != "details-1" {
		t.Fatalf("message identity = (%q, %q), want (%q, details-1)", msg.Type, msg.ID, protocol.MsgTypeKeyDetails)
	}
	if msg.PublicKeyHex != "aabbccdd" {
		t.Fatalf("PublicKeyHex = %q, want aabbccdd", msg.PublicKeyHex)
	}
}

func TestProtocolChangeStorePassphraseResultPreservesFailureRecoveryState(t *testing.T) {
	msg := ProtocolChangeStorePassphraseResultMessage(
		"change-1",
		adminproto.ChangeStorePassphraseResult{
			PriorGenerations: 2,
			HelperWarning:    "helper still has old passphrase",
			RootCommitted:    true,
			Code:             "passphrase_change_failed",
			Error:            "injected completion failure",
		},
	)
	if msg.Success ||
		msg.PriorGenerations != 2 ||
		msg.HelperWarning == "" ||
		!msg.RootCommitted ||
		msg.Code != "passphrase_change_failed" {
		t.Fatalf("failure recovery state was not preserved: %#v", msg)
	}
}

func TestBackupProtocolMessagesDoNotExposeStorePaths(t *testing.T) {
	created := ProtocolBackupResultMessage("backup-1", adminproto.BackupIdentityResult{
		Success: true, ArchivePath: "/var/lib/apsigner/backups/default/created.tar.gz",
	})
	if created.ArchivePath != "created.tar.gz" {
		t.Fatalf("backup archive_path = %q, want basename", created.ArchivePath)
	}

	listed := ProtocolBackupsListMessage("list-1", adminproto.ListBackupsResult{Backups: []adminproto.BackupInfo{{
		Path: "/var/lib/apsigner/backups/default/listed.tar.gz", FileName: "listed.tar.gz",
	}}})
	if len(listed.Backups) != 1 || listed.Backups[0].Path != "listed.tar.gz" || listed.Backups[0].FileName != "listed.tar.gz" {
		t.Fatalf("listed backup leaked path: %#v", listed.Backups)
	}

	committed := ProtocolCommitBackupImportResultMessage("commit-1", adminproto.CommitBackupImportResult{
		Success: true, Warning: "directory durability warning", Backup: adminproto.BackupInfo{
			Path: "/var/lib/apsigner/backups/default/imported.tar.gz", FileName: "imported.tar.gz",
		},
	})
	if committed.Backup.Path != "imported.tar.gz" || committed.Backup.FileName != "imported.tar.gz" {
		t.Fatalf("committed backup leaked path: %#v", committed.Backup)
	}
	if committed.Warning != "directory durability warning" {
		t.Fatalf("committed backup warning = %q", committed.Warning)
	}
}
