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

func TestFormatRecoveredReviewSectionsSeparatesArchiveLimitations(t *testing.T) {
	review := protocol.ReviewRecoveredResultMessage{
		UnknownSourceSettings: []string{
			protocol.RecoverySourceSettingUserAutoApprove,
			protocol.RecoverySourceSettingGenesisHashMappings,
			protocol.RecoverySourceSettingNodeRole,
			"source.future_setting",
		},
	}
	rendered := formatRecoveredReviewSections(review)

	if !strings.Contains(rendered, "Security-bearing policy differences\n  none") {
		t.Fatalf("review omitted new no-difference output:\n%s", rendered)
	}
	if strings.Count(rendered, archiveSourceSettingsLimitation) != 1 {
		t.Fatalf("archive limitation count = %d, want 1:\n%s",
			strings.Count(rendered, archiveSourceSettingsLimitation), rendered)
	}
	if strings.Contains(rendered, "[unknown source] "+protocol.RecoverySourceSettingUserAutoApprove) ||
		strings.Contains(rendered, "[unknown source] "+protocol.RecoverySourceSettingGenesisHashMappings) {
		t.Fatalf("constant archive limitations rendered as findings:\n%s", rendered)
	}
	for _, want := range []string{
		"Source metadata unavailable for this archive",
		"[unknown source] " + protocol.RecoverySourceSettingNodeRole,
		"[unknown source] source.future_setting",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("review omitted %q:\n%s", want, rendered)
		}
	}
}

func TestFormatRecoveredReviewSectionsOrdersSecurityChangesFirst(t *testing.T) {
	rendered := formatRecoveredReviewSections(protocol.ReviewRecoveredResultMessage{
		SecurityChanges: []protocol.RecoveryPolicyChange{{
			Category:    "hard_rejects",
			Path:        "reject_rekey",
			Source:      "true",
			Destination: "false",
		}},
		UnknownSourceSettings: []string{protocol.RecoverySourceSettingNodeRole},
	})
	changeIndex := strings.Index(rendered, "reject_rekey")
	unknownIndex := strings.Index(rendered, protocol.RecoverySourceSettingNodeRole)
	noteIndex := strings.Index(rendered, archiveSourceSettingsLimitation)
	if changeIndex < 0 || unknownIndex < changeIndex || noteIndex < unknownIndex {
		t.Fatalf("review section order is wrong:\n%s", rendered)
	}
}

func TestFormatRecoveredReviewSectionsUsesTypedSourceContextPrecedence(t *testing.T) {
	autoApprove := false
	rendered := formatRecoveredReviewSections(protocol.ReviewRecoveredResultMessage{
		UnknownSourceSettings: []string{
			protocol.RecoverySourceSettingUserAutoApprove,
			protocol.RecoverySourceSettingGenesisHashMappings,
		},
		SourceSettingsStatus:  protocol.RecoverySourceSettingsStatusUnverified,
		SourceUserAutoApprove: &autoApprove,
		SourceGenesisHashMappings: []protocol.RecoveryGenesisHashMapping{{
			GenesisHash: "REREREREREREREREREREREREREREREREREREREREREQ=",
			Network:     "private-network",
		}},
	})
	for _, want := range []string{
		"Unverified archive-reported source context",
		"approval default: manual review",
		"private-network: REREREREREREREREREREREREREREREREREREREREREQ=",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("typed source review omitted %q:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, archiveSourceSettingsLimitation) ||
		strings.Contains(rendered, "[unknown source] "+protocol.RecoverySourceSettingUserAutoApprove) {
		t.Fatalf("typed source review retained superseded v3 caveat:\n%s", rendered)
	}
}

func TestFormatRecoveredReviewSectionsWarnsForInvalidSourceContext(t *testing.T) {
	rendered := formatRecoveredReviewSections(protocol.ReviewRecoveredResultMessage{
		SourceSettingsStatus:  protocol.RecoverySourceSettingsStatusInvalid,
		SourceSettingsWarning: "source settings metadata is invalid: unsupported schema",
	})
	if !strings.Contains(rendered, "WARNING: source settings metadata is invalid") ||
		!strings.Contains(rendered, archiveSourceSettingsLimitation) {
		t.Fatalf("invalid source review omitted warning or limitation:\n%s", rendered)
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
			State:                   "recovered",
			DestinationApprovalMode: "manual_default",
			ReviewToken:             strings.Repeat("a", 64),
		},
		recoveredActivateResult: protocol.ActivateRecoveredResultMessage{
			Success:  true,
			KeyCount: 1,
		},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := withTestStdin("export-passphrase\ny\n", func() error {
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
	if !fake.recoveredActivateRequest.ReplaceExisting ||
		!fake.recoveredActivateRequest.AcknowledgePolicyTransition {
		t.Fatalf("activate request = %+v, want replace and policy acknowledgement", fake.recoveredActivateRequest)
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

func TestCmdRestoreApplyRequiresSeparateUnattendedSigningAcknowledgement(t *testing.T) {
	restoreID := "0123456789abcdef0123456789abcdef"
	fake := &fakeApstoreAdminRequester{
		recoverResult: protocol.RecoverBackupResultMessage{
			Success:   true,
			RestoreID: restoreID,
		},
		recoveredReviewResult: protocol.ReviewRecoveredResultMessage{
			Success:                  true,
			RestoreID:                restoreID,
			State:                    "recovered",
			DestinationApprovalMode:  "auto_approve_fallback",
			UnattendedSigningWarning: "you are activating into an auto-approving identity",
			ReviewToken:              strings.Repeat("a", 64),
		},
		recoveredActivateResult: protocol.ActivateRecoveredResultMessage{Success: true},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := withTestStdin("export-passphrase\ny\ny\n", func() error {
		return cmdRestoreApplyManaged([]string{"restore-source.tar.gz"})
	}); err != nil {
		t.Fatalf("cmdRestoreApplyManaged() error = %v", err)
	}
	if !fake.recoveredActivateRequest.AcknowledgePolicyTransition ||
		!fake.recoveredActivateRequest.AcknowledgeUnattendedSigning {
		t.Fatalf("activation acknowledgements = %+v", fake.recoveredActivateRequest)
	}
}

func TestCmdRestoreActivateResumesOnlyRecordedIntent(t *testing.T) {
	restoreID := "0123456789abcdef0123456789abcdef"
	fake := &fakeApstoreAdminRequester{
		recoveredReviewResult: protocol.ReviewRecoveredResultMessage{
			Success:                     true,
			RestoreID:                   restoreID,
			State:                       "activation_incomplete",
			DestinationApprovalMode:     "manual_default",
			ReviewToken:                 strings.Repeat("b", 64),
			AcknowledgePolicyTransition: true,
		},
		recoveredActivateResult: protocol.ActivateRecoveredResultMessage{Success: true},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := withTestStdin("y\n", func() error {
		return cmdRestoreActivateRecovered([]string{restoreID})
	}); err != nil {
		t.Fatalf("cmdRestoreActivateRecovered() error = %v", err)
	}
	wantRequests := []string{protocol.MsgTypeReviewRecovered, protocol.MsgTypeActivateRecovered}
	if strings.Join(fake.requests, ",") != strings.Join(wantRequests, ",") {
		t.Fatalf("requests = %v, want %v", fake.requests, wantRequests)
	}
	if fake.recoveredActivateRequest.ReviewToken != strings.Repeat("b", 64) ||
		!fake.recoveredActivateRequest.AcknowledgePolicyTransition {
		t.Fatalf("resume request = %+v", fake.recoveredActivateRequest)
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
