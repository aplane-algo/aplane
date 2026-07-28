// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"context"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/backup"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestCmdBackupImportRejectsInvalidSources(t *testing.T) {
	oldDataDirectory := dataDirectory
	dataDirectory = t.TempDir()
	defer func() { dataDirectory = oldDataDirectory }()

	if err := cmdBackupImport(filepath.Join(t.TempDir(), "backup.zip")); err == nil {
		t.Fatal("cmdBackupImport(non-archive) error = nil, want extension rejection")
	} else if !strings.Contains(err.Error(), "must end in .tar.gz or .tgz") {
		t.Fatalf("cmdBackupImport(non-archive) error = %v, want extension context", err)
	}

	if err := cmdBackupImport(filepath.Join(t.TempDir(), "missing.tar.gz")); err == nil {
		t.Fatal("cmdBackupImport(missing) error = nil, want missing source rejection")
	} else if !strings.Contains(err.Error(), "backup source unavailable") {
		t.Fatalf("cmdBackupImport(missing) error = %v, want missing source context", err)
	}
}

func TestFormatRecoveredReviewSectionsRendersAuthenticatedSourceContext(t *testing.T) {
	autoApprove := false
	review := protocol.ReviewRecoveredResultMessage{
		SourceUserAutoApprove: &autoApprove,
		SourceGenesisHashMappings: []protocol.RecoveryGenesisHashMapping{{
			GenesisHash: "REREREREREREREREREREREREREREREREREREREREREQ=",
			Network:     "private-network",
		}},
	}
	rendered := formatRecoveredReviewSections(review)

	if !strings.Contains(rendered, "Policy differences (informational)") ||
		!strings.Contains(rendered, "  none") {
		t.Fatalf("review omitted the no-difference result:\n%s", rendered)
	}
	// Source context renders under a provenance heading that names its
	// scope; the sealed manifest authenticated it, so no trust qualifier
	// appears anywhere.
	if !strings.Contains(rendered, "Reported by the backup archive") ||
		!strings.Contains(rendered, "approval default: manual review") ||
		!strings.Contains(rendered, "private-network") {
		t.Fatalf("review omitted source context:\n%s", rendered)
	}
	for _, stale := range []string{"unverified", "unknown source", "Source metadata unavailable"} {
		if strings.Contains(rendered, stale) {
			t.Fatalf("review rendered trust-state text %q:\n%s", stale, rendered)
		}
	}
}

func TestFormatRecoveredReviewSectionsOmitsAbsentSourceContext(t *testing.T) {
	rendered := formatRecoveredReviewSections(protocol.ReviewRecoveredResultMessage{})
	if strings.Contains(rendered, "Reported by the backup archive") {
		t.Fatalf("review invented a source-context section:\n%s", rendered)
	}
}

func TestFormatRecoveredReviewSectionsRendersChangesWithoutVerdict(t *testing.T) {
	rendered := formatRecoveredReviewSections(protocol.ReviewRecoveredResultMessage{
		SecurityChanges: []protocol.RecoveryPolicyChange{{
			Category:    "hard_rejects",
			Path:        "reject_rekey",
			Source:      "true",
			Destination: "false",
		}},
	})
	if !strings.Contains(rendered, "[hard_rejects]") {
		t.Fatalf("review omitted the policy difference:\n%s", rendered)
	}
	if strings.Contains(rendered, "downgrade") {
		t.Fatalf("review rendered a downgrade verdict:\n%s", rendered)
	}
	// Invariant prose belongs in the documentation, not on every review.
	for _, constant := range []string{
		"Backup archives do not record",
		"cannot be authenticated",
		"Unverified",
	} {
		if strings.Contains(rendered, constant) {
			t.Fatalf("review repeated invariant prose %q:\n%s", constant, rendered)
		}
	}
}

func TestCmdBackupImportRejectsDuplicateBasename(t *testing.T) {
	RegisterProviders()

	oldDataDirectory := dataDirectory
	dataDirectory = t.TempDir()
	defer func() { dataDirectory = oldDataDirectory }()

	backupRoot := t.TempDir()
	address, keyJSON := testEd25519KeyJSON(t)
	if err := writeStandaloneBackup(filepath.Join(backupRoot, "apb"), address, keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackup() error = %v", err)
	}
	archivePath := filepath.Join(t.TempDir(), "restore-source.tar.gz")
	sealTestArchive(t, backupRoot, noderole.RoleSigner)
	if err := backup.CreateTarGzArchive(backupRoot, archivePath); err != nil {
		t.Fatalf("CreateTarGzArchive() error = %v", err)
	}

	if err := withTestStdin("export-passphrase\n", func() error {
		return cmdBackupImport(archivePath)
	}); err != nil {
		t.Fatalf("first cmdBackupImport() error = %v", err)
	}
	err := withTestStdin("export-passphrase\n", func() error {
		return cmdBackupImport(archivePath)
	})
	if err == nil {
		t.Fatal("second cmdBackupImport() error = nil, want duplicate rejection")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second cmdBackupImport() error = %v, want duplicate context", err)
	}
}

func TestBackupImportTemplateValidationClientUsesConfiguredTEALCompileToken(t *testing.T) {
	oldConfig := config
	defer func() { config = oldConfig }()

	var sawCompile bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/teal/compile" {
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
		sawCompile = true
		if got := r.Header.Get("X-Algo-API-Token"); got != "localnet-token" {
			t.Fatalf("X-Algo-API-Token = %q, want localnet-token", got)
		}
		_, _ = w.Write([]byte(`{"result":"AQ==","hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`))
	}))
	defer server.Close()

	config = serverconfig.ServerConfig{
		TEALCompileNetwork: "localnet",
		Algod: apconfig.AlgodConfig{
			"localnet": &apconfig.AlgodNetworkConfig{
				Server: server.URL,
				Token:  "localnet-token",
			},
		},
	}

	client, err := newBackupImportTemplateValidationClient()
	if err != nil {
		t.Fatalf("newBackupImportTemplateValidationClient() error = %v", err)
	}
	if _, err := client.TealCompile([]byte("#pragma version 8\nint 1\n")).Do(context.Background()); err != nil {
		t.Fatalf("TealCompile() error = %v", err)
	}
	if !sawCompile {
		t.Fatal("mock algod did not receive compile request")
	}
}

func TestRestoreKeyRejectsWrongExportPassphrase(t *testing.T) {
	RegisterProviders()

	dataDirectory = t.TempDir()
	backupDir := t.TempDir()
	address, keyJSON := testEd25519KeyJSON(t)

	encrypted, err := apcrypto.EncryptStandalone(keyJSON, []byte("correct-export-passphrase"))
	if err != nil {
		t.Fatalf("EncryptStandalone() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, address+".apb"), encrypted, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	keyType, err := restoreKey(backupDir, address, bytes32(0x11), []byte("wrong-export-passphrase"))
	if err == nil {
		t.Fatal("restoreKey() error = nil, want wrong passphrase failure")
	}
	if keyType != "" {
		t.Fatalf("restoreKey() keyType = %q, want empty on failure", keyType)
	}
	if !strings.Contains(err.Error(), "wrong passphrase") {
		t.Fatalf("restoreKey() error = %v, want wrong passphrase context", err)
	}
}

func TestCmdBackupImportUsesManagedBackupDir(t *testing.T) {
	RegisterProviders()

	oldDataDirectory := dataDirectory
	dataDirectory = t.TempDir()
	defer func() { dataDirectory = oldDataDirectory }()

	backupRoot := t.TempDir()
	address, keyJSON := testEd25519KeyJSON(t)
	if err := writeStandaloneBackup(filepath.Join(backupRoot, "apb"), address, keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackup() error = %v", err)
	}
	archivePath := filepath.Join(t.TempDir(), "restore-source.tar.gz")
	sealTestArchive(t, backupRoot, noderole.RoleSigner)
	if err := backup.CreateTarGzArchive(backupRoot, archivePath); err != nil {
		t.Fatalf("CreateTarGzArchive() error = %v", err)
	}

	if err := withTestStdin("export-passphrase\n", func() error {
		return cmdBackupImport(archivePath)
	}); err != nil {
		t.Fatalf("cmdBackupImport() error = %v", err)
	}
	importedPath := filepath.Join(keystorePaths().IdentityBackupsDir(productIdentityID()), filepath.Base(archivePath))
	if _, err := os.Stat(importedPath); err != nil {
		t.Fatalf("imported archive stat error = %v", err)
	}
	items, err := backup.ListManagedBackups(keystorePaths(), productIdentityID())
	if err != nil {
		t.Fatalf("ListManagedBackups() error = %v", err)
	}
	if len(items) != 1 || items[0].FileName != filepath.Base(archivePath) {
		t.Fatalf("managed backups = %+v, want %s", items, filepath.Base(archivePath))
	}
	if len(items) != 1 || !items[0].Verified {
		t.Fatalf("managed backup import = %+v, want verified listed item", items)
	}
}

func TestCmdRestoreApplyManagedRecoversReviewsAndActivates(t *testing.T) {
	restoreID := "0123456789abcdef0123456789abcdef"
	fake := &fakeApstoreAdminRequester{
		recoverResult: protocol.RecoverBackupResultMessage{
			Success:    true,
			RestoreID:  restoreID,
			EntryCount: 1,
		},
		recoveredReviewResult: protocol.ReviewRecoveredResultMessage{
			Success:                 true,
			RestoreID:               restoreID,
			DestinationApprovalMode: "manual_default",
			ReviewToken:             strings.Repeat("a", 64),
		},
		recoveredActivateResult: protocol.ActivateRecoveredResultMessage{
			Success:  true,
			KeyCount: 1,
		},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := withTestStdin("export-passphrase\n", func() error {
		return cmdRestoreApplyManaged([]string{"restore-source.tar.gz", "--address", "ADDR", "--overwrite"})
	}); err != nil {
		t.Fatalf("cmdRestoreApplyManaged() error = %v", err)
	}

	wantRequests := []string{
		protocol.MsgTypeRecoverBackup,
		protocol.MsgTypeReviewRecovered,
		protocol.MsgTypeActivateRecovered,
	}
	if strings.Join(fake.requests, ",") != strings.Join(wantRequests, ",") {
		t.Fatalf("requests = %v, want %v", fake.requests, wantRequests)
	}
	if fake.recoverRequest.ArchivePath != "restore-source.tar.gz" {
		t.Fatalf("recover archive = %q, want restore-source.tar.gz", fake.recoverRequest.ArchivePath)
	}
	if len(fake.recoverRequest.Addresses) != 1 || fake.recoverRequest.Addresses[0] != "ADDR" {
		t.Fatalf("recover addresses = %v, want [ADDR]", fake.recoverRequest.Addresses)
	}
	if !fake.recoveredActivateRequest.ReplaceExisting {
		t.Fatalf("activate request = %+v, want replace_existing", fake.recoveredActivateRequest)
	}
}

func TestCmdRestoreApplyManagedStopsWhenRecoveryFails(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		recoverResult: protocol.RecoverBackupResultMessage{
			Code:  protocol.ResultCodeRecoverBackupFailed,
			Error: "bad backup",
		},
	}
	withFakeApstoreAdminClient(t, fake)

	err := withTestStdin("export-passphrase\n", func() error {
		return cmdRestoreApplyManaged([]string{"restore-source.tar.gz"})
	})
	if err == nil {
		t.Fatal("cmdRestoreApplyManaged() error = nil, want recovery failure")
	}
	if !strings.Contains(err.Error(), "bad backup") {
		t.Fatalf("cmdRestoreApplyManaged() error = %v, want bad backup", err)
	}
	wantRequests := []string{protocol.MsgTypeRecoverBackup}
	if strings.Join(fake.requests, ",") != strings.Join(wantRequests, ",") {
		t.Fatalf("requests = %v, want %v", fake.requests, wantRequests)
	}
}

func TestCmdRestoreApplyManagedStopsWhenBackupArchiveMissing(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		recoverResult: protocol.RecoverBackupResultMessage{
			Code:  "backup_not_found",
			Error: "backup archive not found",
		},
	}
	withFakeApstoreAdminClient(t, fake)

	err := withTestStdin("export-passphrase\n", func() error {
		return cmdRestoreApplyManaged([]string{"missing.tar.gz"})
	})
	if err == nil {
		t.Fatal("cmdRestoreApplyManaged() error = nil, want missing backup archive failure")
	}
	if !strings.Contains(err.Error(), "backup archive not found") {
		t.Fatalf("cmdRestoreApplyManaged() error = %v, want missing archive context", err)
	}
	wantRequests := []string{protocol.MsgTypeRecoverBackup}
	if strings.Join(fake.requests, ",") != strings.Join(wantRequests, ",") {
		t.Fatalf("requests = %v, want %v", fake.requests, wantRequests)
	}
}

// --acknowledge-unattended-signing records the acknowledgement without a
// prompt, so restore stays scriptable against an auto-approving destination.
func TestCmdRestoreApplyAcceptsUnattendedAcknowledgementFlag(t *testing.T) {
	restoreID := "0123456789abcdef0123456789abcdef"
	unattendedAckRequired := true
	fake := &fakeApstoreAdminRequester{
		recoverResult: protocol.RecoverBackupResultMessage{
			Success:   true,
			RestoreID: restoreID,
		},
		recoveredReviewResult: protocol.ReviewRecoveredResultMessage{
			Success:                      true,
			RestoreID:                    restoreID,
			DestinationApprovalMode:      "auto_approve_fallback",
			UnattendedSigningWarning:     "you are activating into an auto-approving identity",
			ReviewToken:                  strings.Repeat("a", 64),
			UnattendedSigningAckRequired: &unattendedAckRequired,
		},
		recoveredActivateResult: protocol.ActivateRecoveredResultMessage{Success: true},
	}
	withFakeApstoreAdminClient(t, fake)

	// Only the export passphrase is supplied: no prompt may be read.
	if err := withTestStdin("export-passphrase\n", func() error {
		return cmdRestoreApplyManaged([]string{
			"restore-source.tar.gz",
			"--acknowledge-unattended-signing",
		})
	}); err != nil {
		t.Fatalf("cmdRestoreApplyManaged(flag) error = %v", err)
	}
	if !fake.recoveredActivateRequest.AcknowledgeUnattendedSigning {
		t.Fatalf("activation request = %+v, want recorded acknowledgement", fake.recoveredActivateRequest)
	}
}

// The flag is explicit intent, not a blanket opt-out: a destination that does
// not auto-approve still sends no acknowledgement.
func TestCmdRestoreApplyFlagDoesNotAcknowledgeWhenNotRequired(t *testing.T) {
	restoreID := "0123456789abcdef0123456789abcdef"
	unattendedAckRequired := false
	fake := &fakeApstoreAdminRequester{
		recoverResult: protocol.RecoverBackupResultMessage{
			Success:   true,
			RestoreID: restoreID,
		},
		recoveredReviewResult: protocol.ReviewRecoveredResultMessage{
			Success:                      true,
			RestoreID:                    restoreID,
			DestinationApprovalMode:      "manual_default",
			ReviewToken:                  strings.Repeat("a", 64),
			UnattendedSigningAckRequired: &unattendedAckRequired,
		},
		recoveredActivateResult: protocol.ActivateRecoveredResultMessage{Success: true},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := withTestStdin("export-passphrase\n", func() error {
		return cmdRestoreApplyManaged([]string{
			"restore-source.tar.gz",
			"--acknowledge-unattended-signing",
		})
	}); err != nil {
		t.Fatalf("cmdRestoreApplyManaged(flag) error = %v", err)
	}
	if fake.recoveredActivateRequest.AcknowledgeUnattendedSigning {
		t.Fatalf("activation request = %+v, want no acknowledgement", fake.recoveredActivateRequest)
	}
}

func TestCmdRestoreApplyRequiresSeparateUnattendedSigningAcknowledgement(t *testing.T) {
	restoreID := "0123456789abcdef0123456789abcdef"
	unattendedAckRequired := true
	fake := &fakeApstoreAdminRequester{
		recoverResult: protocol.RecoverBackupResultMessage{
			Success:   true,
			RestoreID: restoreID,
		},
		recoveredReviewResult: protocol.ReviewRecoveredResultMessage{
			Success:                      true,
			RestoreID:                    restoreID,
			DestinationApprovalMode:      "auto_approve_fallback",
			UnattendedSigningWarning:     "you are activating into an auto-approving identity",
			ReviewToken:                  strings.Repeat("a", 64),
			UnattendedSigningAckRequired: &unattendedAckRequired,
		},
		recoveredActivateResult: protocol.ActivateRecoveredResultMessage{Success: true},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := withTestStdin("export-passphrase\ny\n", func() error {
		return cmdRestoreApplyManaged([]string{"restore-source.tar.gz"})
	}); err != nil {
		t.Fatalf("cmdRestoreApplyManaged() error = %v", err)
	}
	if !fake.recoveredActivateRequest.AcknowledgeUnattendedSigning {
		t.Fatalf("activation acknowledgements = %+v", fake.recoveredActivateRequest)
	}
}

func TestRecoveredUnattendedSigningAckRequiredTreatsMissingFieldAsLegacy(t *testing.T) {
	if !recoveredUnattendedSigningAckRequired(protocol.ReviewRecoveredResultMessage{
		DestinationApprovalMode: "auto_approve_fallback",
	}) {
		t.Fatal("missing unattended-signing requirement did not use conservative legacy fallback")
	}
	required := false
	if recoveredUnattendedSigningAckRequired(protocol.ReviewRecoveredResultMessage{
		DestinationApprovalMode:      "auto_approve_fallback",
		UnattendedSigningAckRequired: &required,
	}) {
		t.Fatal("explicit false unattended-signing requirement was ignored")
	}
}

func TestCmdRestoreRollbackAndPurgeUseExplicitOperations(t *testing.T) {
	restoreID := "0123456789abcdef0123456789abcdef"
	rollbackFake := &fakeApstoreAdminRequester{
		recoveredRollbackResult: protocol.RollbackRecoveredResultMessage{Success: true},
	}
	withFakeApstoreAdminClient(t, rollbackFake)
	if err := withTestStdin("y\n", func() error {
		return cmdRestoreRollbackRecovered(restoreID)
	}); err != nil {
		t.Fatalf("cmdRestoreRollbackRecovered() error = %v", err)
	}
	if len(rollbackFake.requests) != 1 || rollbackFake.requests[0] != protocol.MsgTypeRollbackRecovered {
		t.Fatalf("rollback requests = %v", rollbackFake.requests)
	}

	purgeFake := &fakeApstoreAdminRequester{
		recoveredPurgeResult: protocol.PurgeRecoveredResultMessage{Success: true},
	}
	withFakeApstoreAdminClient(t, purgeFake)
	if err := withTestStdin("y\n", func() error {
		return cmdRestorePurgeRecovered(restoreID)
	}); err != nil {
		t.Fatalf("cmdRestorePurgeRecovered() error = %v", err)
	}
	if len(purgeFake.requests) != 1 || purgeFake.requests[0] != protocol.MsgTypePurgeRecovered {
		t.Fatalf("purge requests = %v", purgeFake.requests)
	}
}

func TestFormatRecoveredReviewSectionsMarksUnavailableComparison(t *testing.T) {
	rendered := formatRecoveredReviewSections(protocol.ReviewRecoveredResultMessage{
		PolicyComparison: string(policy.RestoreComparisonUnavailable),
	})
	if strings.Contains(rendered, "  none") {
		t.Fatalf("unavailable comparison rendered as a no-difference all-clear:\n%s", rendered)
	}
	if !strings.Contains(rendered, "comparison unavailable") {
		t.Fatalf("unavailable comparison not surfaced:\n%s", rendered)
	}
}
