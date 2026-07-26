// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/backup/recovered"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storepass"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

var backupAdminTestPassphrase = []byte("backup-admin-test-passphrase")

func TestManagedBackupTimestampIncludesNanoseconds(t *testing.T) {
	first := managedBackupTimestamp(time.Unix(1700000000, 1))
	second := managedBackupTimestamp(time.Unix(1700000000, 2))
	if first == second {
		t.Fatalf("timestamps are equal: %q", first)
	}
	if !strings.HasSuffix(first, ".000000001") {
		t.Fatalf("timestamp = %q, want nanosecond precision", first)
	}
}

func TestBackupIdentityZeroesRequestPassphraseOnFailure(t *testing.T) {
	passphrase := []byte("export-passphrase")
	service := Service{
		Deps: failingBackupDeps{
			paths: storepaths.NewPaths(t.TempDir()),
		},
	}
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("token"),
	})

	result := service.BackupIdentity(ir, adminproto.BackupIdentityRequest{
		ExportPassphrase: passphrase,
	})

	if result.Success {
		t.Fatal("BackupIdentity() success = true, want failure")
	}
	for i, b := range passphrase {
		if b != 0 {
			t.Fatalf("passphrase byte %d = %d, want zero", i, b)
		}
	}
}

func TestBackupIdentityCapturesSourceApprovalAndCustomGenesisMappings(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	customGenesisHash := strings.Repeat("34", 32)
	service := Service{
		Deps: backupServiceTestDeps{
			paths: paths,
			genesisHashMappings: map[string]string{
				customGenesisHash: "private-network",
			},
		},
	}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntimeWithAutoApprove(t, paths, &reloads, true)
	if _, _, err := noderole.SaveInitial(paths, noderole.RoleSigner, time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatalf("SaveInitial(node role) error = %v", err)
	}
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})
	address, keyJSON := keystest.Ed25519KeyJSON(t)
	defer crypto.ZeroBytes(keyJSON)
	if err := ir.WithMasterKey(func(masterKey []byte) error {
		encrypted, err := crypto.EncryptWithMasterKey(keyJSON, masterKey)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(paths.KeysDir(auth.DefaultIdentityID), 0o770); err != nil {
			return err
		}
		return os.WriteFile(
			keys.AccountKeyFilePath(paths, auth.DefaultIdentityID, address),
			encrypted,
			0o600,
		)
	}); err != nil {
		t.Fatalf("write active key: %v", err)
	}

	result := service.BackupIdentity(ir, adminproto.BackupIdentityRequest{
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !result.Success {
		t.Fatalf("BackupIdentity() = %+v, want success", result)
	}
	extractDir := t.TempDir()
	if err := backup.ExtractTarGzArchive(result.ArchivePath, extractDir); err != nil {
		t.Fatalf("ExtractTarGzArchive() error = %v", err)
	}
	data, err := os.ReadFile(filepath.Join(extractDir, backup.SourceSettingsFileName))
	if err != nil {
		t.Fatalf("ReadFile(source settings) error = %v", err)
	}
	var document struct {
		UserAutoApprove     *bool `json:"user_auto_approve"`
		GenesisHashMappings []struct {
			GenesisHash string `json:"genesis_hash"`
			Network     string `json:"network"`
		} `json:"genesis_hash_mappings"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("Unmarshal(source settings) error = %v", err)
	}
	if document.UserAutoApprove == nil || !*document.UserAutoApprove {
		t.Fatalf("source user_auto_approve = %v, want true", document.UserAutoApprove)
	}
	if len(document.GenesisHashMappings) != 1 ||
		document.GenesisHashMappings[0].Network != "private-network" ||
		document.GenesisHashMappings[0].GenesisHash == customGenesisHash {
		t.Fatalf(
			"source genesis-hash mappings = %+v, want one canonical private-network mapping",
			document.GenesisHashMappings,
		)
	}
	for _, forbidden := range []string{"algod_token", "algod_url", "endpoint"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("source settings contain forbidden field %q: %s", forbidden, data)
		}
	}
}

func TestPreviewRestoreRecordsLimiterFailureForMalformedArchive(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath := writeMalformedManagedArchive(t, paths, auth.DefaultIdentityID, "preview")
	limiter := NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) })
	service := Service{
		Deps: backupServiceTestDeps{
			paths:   paths,
			limiter: limiter,
		},
	}
	ir := testBackupIdentityRuntime()

	result := service.PreviewRestore(ir, adminproto.PreviewRestoreRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})

	if result.Code != protocol.ResultCodeRestorePreviewFailed {
		t.Fatalf("PreviewRestore().Code = %q, want %s", result.Code, protocol.ResultCodeRestorePreviewFailed)
	}
	if retryAfter := limiter.RetryAfter(auth.DefaultIdentityID, archivePath); retryAfter == 0 {
		t.Fatal("RetryAfter() = 0, want malformed preview to record limiter failure")
	}

	limited := service.PreviewRestore(ir, adminproto.PreviewRestoreRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if limited.Code != protocol.ResultCodeRestoreRateLimited {
		t.Fatalf("second PreviewRestore().Code = %q, want %s", limited.Code, protocol.ResultCodeRestoreRateLimited)
	}
}

func TestRecoverBackupAndListRecoveredDoNotReloadOrActivate(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath, address := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	limiter := NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) })
	service := Service{
		Deps: backupServiceTestDeps{
			paths:   paths,
			limiter: limiter,
		},
	}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	exportPassphrase := []byte("export-passphrase")

	result := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: exportPassphrase,
	})
	if !result.Success || result.RestoreID == "" || result.EntryCount != 1 {
		t.Fatalf("RecoverBackup() = %+v, want one inactive batch", result)
	}
	for i, b := range exportPassphrase {
		if b != 0 {
			t.Fatalf("export passphrase byte %d = %d, want zero", i, b)
		}
	}
	if got := reloads.Load(); got != 0 {
		t.Fatalf("runtime reload count = %d, want 0", got)
	}
	if _, err := os.Stat(keys.AccountKeyFilePath(paths, auth.DefaultIdentityID, address)); !os.IsNotExist(err) {
		t.Fatalf("active key stat error = %v, want not found", err)
	}

	listed := service.ListRecovered(ir)
	if listed.Error != "" || len(listed.Batches) != 1 {
		t.Fatalf("ListRecovered() = %+v, want one batch", listed)
	}
	if listed.Batches[0].RestoreID != result.RestoreID ||
		listed.Batches[0].ArchiveChecksum != result.ArchiveChecksum ||
		listed.Batches[0].EntryCount != 1 {
		t.Fatalf("ListRecovered() batch = %+v, want result %+v", listed.Batches[0], result)
	}
	if got := reloads.Load(); got != 0 {
		t.Fatalf("runtime reload count after list = %d, want 0", got)
	}
}

func TestRecoverAndListRecoveredFailWithoutMasterKey(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath, _ := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	service := Service{
		Deps: backupServiceTestDeps{
			paths:   paths,
			limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
		},
	}
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		KeyStore:      keystore.NewFileKeyStoreForPaths(paths, auth.DefaultIdentityID),
		KeyPaths:      paths,
		Authenticator: auth.NewTokenAuthenticator("token"),
		NodeRole:      noderole.RoleSigner,
	})

	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if recoverResult.Code != protocol.ResultCodeRecoverBackupFailed ||
		!strings.Contains(recoverResult.Error, "keystore not unlocked") {
		t.Fatalf("RecoverBackup(locked) = %+v, want locked failure", recoverResult)
	}
	listResult := service.ListRecovered(ir)
	if listResult.Code != protocol.ResultCodeListRecoveredFailed ||
		!strings.Contains(listResult.Error, "keystore not unlocked") {
		t.Fatalf("ListRecovered(locked) = %+v, want locked failure", listResult)
	}
	if _, err := os.Stat(paths.RecoveredRootDir(auth.DefaultIdentityID)); !os.IsNotExist(err) {
		t.Fatalf("recovered root stat error = %v, want not found", err)
	}
}

func TestRecoveredBatchSurvivesPassphraseRotationAndActivation(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath, address := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	service := Service{
		Deps: backupServiceTestDeps{
			paths:   paths,
			limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
		},
	}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})
	roleBytes, _, err := noderole.SaveInitial(paths, noderole.RoleSigner, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("SaveInitial(node role) error = %v", err)
	}
	if err := ir.WithMasterKey(func(masterKey []byte) error {
		return noderole.SaveIdentitySidecarWithMasterKey(
			paths,
			auth.DefaultIdentityID,
			roleBytes,
			masterKey,
			time.Unix(1_700_000_000, 0),
		)
	}); err != nil {
		t.Fatalf("SaveIdentitySidecarWithMasterKey() error = %v", err)
	}

	recoveredResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !recoveredResult.Success {
		t.Fatalf("RecoverBackup() = %+v", recoveredResult)
	}

	newPassphrase := []byte("backup-admin-rotated-passphrase")
	rotation, err := storepass.Rotate(
		paths,
		auth.DefaultIdentityID,
		append([]byte(nil), backupAdminTestPassphrase...),
		newPassphrase,
		storepass.RotateOptions{},
	)
	if err != nil {
		t.Fatalf("storepass.Rotate() error = %v", err)
	}
	if rotation.RecoveredFilesMigrated != 2 {
		t.Fatalf("RecoveredFilesMigrated = %d, want batch plus entry", rotation.RecoveredFilesMigrated)
	}
	if _, err := ir.KeyStore().InitializeMasterKey(newPassphrase); err != nil {
		t.Fatalf("InitializeMasterKey(rotated passphrase) error = %v", err)
	}

	review := service.ReviewRecovered(ir, recoveredResult.RestoreID)
	if !review.Success {
		t.Fatalf("ReviewRecovered(after rotation) = %+v", review)
	}
	activated := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:                   recoveredResult.RestoreID,
		ReviewToken:                 review.ReviewToken,
		AcknowledgePolicyTransition: true,
	})
	if !activated.Success {
		t.Fatalf("ActivateRecovered(after rotation) = %+v", activated)
	}
	if _, err := os.Stat(keys.AccountKeyFilePath(paths, auth.DefaultIdentityID, address)); err != nil {
		t.Fatalf("active key after rotated activation stat error = %v", err)
	}
}

func TestReviewRecoveredForegroundsAutoApproveAndPinsDestinationState(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath, address := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	service := Service{
		Deps: backupServiceTestDeps{
			paths:   paths,
			limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
		},
	}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntimeWithAutoApprove(t, paths, &reloads, true)
	destination := &policy.StoredConfig{
		StoredPolicyCore: policy.StoredPolicyCore{
			RejectForeignRekey: boolPointer(false),
			MaxFeeMicroAlgos:   uint64Pointer(1_000),
		},
	}
	installBackupAdminPolicy(t, ir, paths, destination)

	recoveredResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !recoveredResult.Success {
		t.Fatalf("RecoverBackup() = %+v", recoveredResult)
	}
	first := service.ReviewRecovered(ir, recoveredResult.RestoreID)
	if !first.Success {
		t.Fatalf("ReviewRecovered() = %+v", first)
	}
	if first.DestinationApprovalMode != adminproto.DestinationApprovalAutoApproveFallback ||
		first.UnattendedSigningWarning == "" {
		t.Fatalf("destination approval review = mode %q warning %q", first.DestinationApprovalMode, first.UnattendedSigningWarning)
	}
	if first.PolicyComparison != string(policy.RestoreComparisonDifferent) ||
		len(first.SecurityChanges) == 0 ||
		first.SecurityChanges[0].Category != string(policy.RestoreCategoryHardRejects) {
		t.Fatalf("security-first comparison = status %q changes %+v", first.PolicyComparison, first.SecurityChanges)
	}
	if len(first.UnknownSourceSettings) != 2 ||
		!slices.Contains(first.UnknownSourceSettings, protocol.RecoverySourceSettingUserAutoApprove) ||
		!slices.Contains(first.UnknownSourceSettings, protocol.RecoverySourceSettingGenesisHashMappings) {
		t.Fatalf("unknown source settings = %v, want current archive limitations", first.UnknownSourceSettings)
	}
	if first.SourceSettingsStatus != protocol.RecoverySourceSettingsStatusMissing ||
		first.SourceUserAutoApprove != nil ||
		len(first.SourceGenesisHashMappings) != 0 ||
		first.SourceSettingsWarning != "" {
		t.Fatalf("missing source settings review = %+v", first)
	}
	if first.ReviewToken == "" {
		t.Fatal("review token is empty")
	}
	repeated := service.ReviewRecovered(ir, recoveredResult.RestoreID)
	if repeated.ReviewToken != first.ReviewToken {
		t.Fatalf("unchanged review token = %q, want %q", repeated.ReviewToken, first.ReviewToken)
	}

	if err := os.MkdirAll(paths.KeysDir(auth.DefaultIdentityID), 0o750); err != nil {
		t.Fatalf("MkdirAll(keys) error = %v", err)
	}
	if err := os.WriteFile(keys.AccountKeyFilePath(paths, auth.DefaultIdentityID, address), []byte("existing encrypted credential"), 0o600); err != nil {
		t.Fatalf("WriteFile(active conflict) error = %v", err)
	}
	withConflict := service.ReviewRecovered(ir, recoveredResult.RestoreID)
	if len(withConflict.ActiveConflicts) != 1 || withConflict.ReviewToken == first.ReviewToken {
		t.Fatalf("conflict review = conflicts %+v token %q, want one conflict and changed token", withConflict.ActiveConflicts, withConflict.ReviewToken)
	}

	ir.Config().SetUserAutoApprove(false)
	manual := service.ReviewRecovered(ir, recoveredResult.RestoreID)
	if manual.DestinationApprovalMode != adminproto.DestinationApprovalManualDefault ||
		manual.UnattendedSigningWarning != "" ||
		manual.ReviewToken == withConflict.ReviewToken {
		t.Fatalf("manual review = mode %q warning %q token %q", manual.DestinationApprovalMode, manual.UnattendedSigningWarning, manual.ReviewToken)
	}

	matching := &policy.StoredConfig{
		StoredPolicyCore: policy.StoredPolicyCore{
			RejectForeignRekey: boolPointer(true),
		},
	}
	installBackupAdminPolicy(t, ir, paths, matching)
	changedPolicy := service.ReviewRecovered(ir, recoveredResult.RestoreID)
	if changedPolicy.DestinationPolicySHA256 == manual.DestinationPolicySHA256 ||
		changedPolicy.ReviewToken == manual.ReviewToken {
		t.Fatalf("policy change did not stale review: before %+v after %+v", manual, changedPolicy)
	}
	if got := reloads.Load(); got != 0 {
		t.Fatalf("runtime reload count = %d, want 0", got)
	}
}

func TestReviewRecoveredCarriesUnverifiedSourceSettingsAndPinsDigest(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genesisHash := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 32))
	sourceSettings, err := json.Marshal(map[string]any{
		"schema":            backup.SourceSettingsSchema,
		"schema_version":    backup.SourceSettingsSchemaVersion,
		"user_auto_approve": false,
		"genesis_hash_mappings": []map[string]string{{
			"genesis_hash": genesisHash,
			"network":      "private-network",
		}},
	})
	if err != nil {
		t.Fatalf("Marshal(source settings) error = %v", err)
	}
	archivePath, _ := writeRecoverableArchiveWithSourceSettings(
		t,
		paths,
		auth.DefaultIdentityID,
		noderole.RoleSigner,
		true,
		sourceSettings,
	)
	service := Service{
		Deps: backupServiceTestDeps{
			paths:   paths,
			limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
		},
	}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})

	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !recoverResult.Success {
		t.Fatalf("RecoverBackup() = %+v", recoverResult)
	}
	review := service.ReviewRecovered(ir, recoverResult.RestoreID)
	if !review.Success ||
		review.SourceSettingsStatus != protocol.RecoverySourceSettingsStatusUnverified ||
		review.SourceUserAutoApprove == nil ||
		*review.SourceUserAutoApprove ||
		len(review.SourceGenesisHashMappings) != 1 ||
		review.SourceGenesisHashMappings[0].GenesisHash != genesisHash ||
		review.SourceGenesisHashMappings[0].Network != "private-network" ||
		review.SourceSettingsWarning != "" {
		t.Fatalf("ReviewRecovered() source settings = %+v", review)
	}
	if len(review.UnknownSourceSettings) != 2 {
		t.Fatalf(
			"protocol-v3 compatibility unknowns = %v, want two conservative entries",
			review.UnknownSourceSettings,
		)
	}
	ir.Config().SetUserAutoApprove(true)
	autoApproveReview := service.ReviewRecovered(ir, recoverResult.RestoreID)
	if autoApproveReview.DestinationApprovalMode != adminproto.DestinationApprovalAutoApproveFallback ||
		autoApproveReview.UnattendedSigningWarning == "" {
		t.Fatalf("destination auto-approve warning was suppressed: %+v", autoApproveReview)
	}
	missingUnattendedAck := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:                   recoverResult.RestoreID,
		ReviewToken:                 autoApproveReview.ReviewToken,
		AcknowledgePolicyTransition: true,
	})
	if missingUnattendedAck.Code != protocol.ResultCodeActivationAckRequired ||
		!strings.Contains(missingUnattendedAck.Error, "unattended-signing") {
		t.Fatalf(
			"source manual-approval claim waived destination acknowledgement: %+v",
			missingUnattendedAck,
		)
	}

	baseToken, err := recoveredReviewToken(recoveredReviewTokenInput{
		FormatVersion:           recoveredReviewFormatVersion,
		RestoreID:               recoverResult.RestoreID,
		ArchiveSHA256:           strings.Repeat("a", 64),
		SourcePolicyStatus:      string(recovered.SourcePolicyMissing),
		SourceSettingsStatus:    protocol.RecoverySourceSettingsStatusMissing,
		DestinationPolicySHA256: strings.Repeat("b", 64),
		DestinationApprovalMode: string(adminproto.DestinationApprovalManualDefault),
		PolicyComparisonFormat:  recoveredReviewFormatVersion,
	})
	if err != nil {
		t.Fatalf("recoveredReviewToken(missing) error = %v", err)
	}
	changedToken, err := recoveredReviewToken(recoveredReviewTokenInput{
		FormatVersion:           recoveredReviewFormatVersion,
		RestoreID:               recoverResult.RestoreID,
		ArchiveSHA256:           strings.Repeat("a", 64),
		SourcePolicyStatus:      string(recovered.SourcePolicyMissing),
		SourceSettingsStatus:    protocol.RecoverySourceSettingsStatusUnverified,
		SourceSettingsSHA256:    strings.Repeat("c", 64),
		DestinationPolicySHA256: strings.Repeat("b", 64),
		DestinationApprovalMode: string(adminproto.DestinationApprovalManualDefault),
		PolicyComparisonFormat:  recoveredReviewFormatVersion,
	})
	if err != nil {
		t.Fatalf("recoveredReviewToken(unverified) error = %v", err)
	}
	if changedToken == baseToken {
		t.Fatal("source-settings status and digest did not change review token")
	}
}

func TestReviewRecoveredCarriesInvalidSourceSettingsWarning(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath, _ := writeRecoverableArchiveWithSourceSettings(
		t,
		paths,
		auth.DefaultIdentityID,
		noderole.RoleSigner,
		true,
		[]byte(`{"schema":"unsupported"}`),
	)
	service := Service{
		Deps: backupServiceTestDeps{
			paths:   paths,
			limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
		},
	}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})
	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !recoverResult.Success {
		t.Fatalf("RecoverBackup() = %+v", recoverResult)
	}
	review := service.ReviewRecovered(ir, recoverResult.RestoreID)
	if !review.Success ||
		review.SourceSettingsStatus != protocol.RecoverySourceSettingsStatusInvalid ||
		review.SourceSettingsWarning == "" ||
		review.SourceUserAutoApprove != nil ||
		len(review.SourceGenesisHashMappings) != 0 {
		t.Fatalf("ReviewRecovered() invalid source settings = %+v", review)
	}
}

func TestReviewRecoveredReportsLegacySourceRoleSeparately(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath, _ := writeRecoverableArchiveWithoutManifest(
		t,
		paths,
		auth.DefaultIdentityID,
		noderole.RoleSigner,
	)
	service := Service{
		Deps: backupServiceTestDeps{
			paths:   paths,
			limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
		},
	}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})

	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !recoverResult.Success {
		t.Fatalf("RecoverBackup() = %+v", recoverResult)
	}
	review := service.ReviewRecovered(ir, recoverResult.RestoreID)
	if !review.Success {
		t.Fatalf("ReviewRecovered() = %+v", review)
	}
	if len(review.UnknownSourceSettings) != 3 ||
		!slices.Contains(review.UnknownSourceSettings, protocol.RecoverySourceSettingUserAutoApprove) ||
		!slices.Contains(review.UnknownSourceSettings, protocol.RecoverySourceSettingGenesisHashMappings) ||
		!slices.Contains(review.UnknownSourceSettings, protocol.RecoverySourceSettingNodeRole) {
		t.Fatalf("unknown source settings = %v, want limitations plus legacy node role", review.UnknownSourceSettings)
	}
}

func TestActivateRecoveredRequiresCurrentReviewAndAcknowledgements(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath, address := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	service := Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntimeWithAutoApprove(t, paths, &reloads, true)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})
	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	review := service.ReviewRecovered(ir, recoverResult.RestoreID)
	if !review.Success {
		t.Fatalf("ReviewRecovered() = %+v", review)
	}

	stale := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:                   recoverResult.RestoreID,
		ReviewToken:                 strings.Repeat("0", 64),
		AcknowledgePolicyTransition: true,
	})
	if stale.Code != protocol.ResultCodeActivationReviewStale {
		t.Fatalf("ActivateRecovered(stale).Code = %q, want %q", stale.Code, protocol.ResultCodeActivationReviewStale)
	}
	missingPolicyAck := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:   recoverResult.RestoreID,
		ReviewToken: review.ReviewToken,
	})
	if missingPolicyAck.Code != protocol.ResultCodeActivationAckRequired {
		t.Fatalf("ActivateRecovered(no policy ack).Code = %q", missingPolicyAck.Code)
	}
	missingUnattendedAck := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:                   recoverResult.RestoreID,
		ReviewToken:                 review.ReviewToken,
		AcknowledgePolicyTransition: true,
	})
	if missingUnattendedAck.Code != protocol.ResultCodeActivationAckRequired {
		t.Fatalf("ActivateRecovered(no unattended ack).Code = %q", missingUnattendedAck.Code)
	}
	if _, err := os.Stat(keys.AccountKeyFilePath(paths, auth.DefaultIdentityID, address)); !os.IsNotExist(err) {
		t.Fatalf("active key before acknowledged activation stat error = %v, want not found", err)
	}
	if got := reloads.Load(); got != 0 {
		t.Fatalf("reload count before activation = %d, want 0", got)
	}

	activated := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:                    recoverResult.RestoreID,
		ReviewToken:                  review.ReviewToken,
		AcknowledgePolicyTransition:  true,
		AcknowledgeUnattendedSigning: true,
	})
	if !activated.Success || len(activated.Activated) != 1 {
		t.Fatalf("ActivateRecovered() = %+v", activated)
	}
	if _, err := os.Stat(keys.AccountKeyFilePath(paths, auth.DefaultIdentityID, address)); err != nil {
		t.Fatalf("active key stat error = %v", err)
	}
	if _, err := os.Stat(paths.RecoveredBatchDir(auth.DefaultIdentityID, recoverResult.RestoreID)); !os.IsNotExist(err) {
		t.Fatalf("completed recovered batch stat error = %v, want not found", err)
	}
	if got := reloads.Load(); got != 1 {
		t.Fatalf("reload count = %d, want 1", got)
	}
}

func TestSentryRecoveryPublishesWitnessMetadataOnlyOnActivation(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath, componentKey := writeRecoverableSentryArchive(t, paths, auth.DefaultIdentityID)
	service := Service{
		Deps: backupServiceTestDeps{
			paths:   paths,
			limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
		},
	}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntimeForRole(t, paths, &reloads, noderole.RoleSentry, false)
	installBackupAdminPolicyForRole(t, ir, paths, &policy.StoredConfig{}, noderole.RoleSentry)

	recoveredResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !recoveredResult.Success {
		t.Fatalf("RecoverBackup(sentry) = %+v", recoveredResult)
	}
	if _, err := os.Stat(keys.SentryCredentialFilePath(paths, auth.DefaultIdentityID, componentKey)); !os.IsNotExist(err) {
		t.Fatalf("active sentry credential before activation stat error = %v, want not found", err)
	}
	metadataPath := keys.WitnessPublicMetadataPath(paths, auth.DefaultIdentityID, componentKey)
	if _, err := os.Stat(metadataPath); !os.IsNotExist(err) {
		t.Fatalf("witness metadata before activation stat error = %v, want not found", err)
	}

	review := service.ReviewRecovered(ir, recoveredResult.RestoreID)
	if !review.Success {
		t.Fatalf("ReviewRecovered(sentry) = %+v", review)
	}
	activated := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:                   recoveredResult.RestoreID,
		ReviewToken:                 review.ReviewToken,
		AcknowledgePolicyTransition: true,
	})
	if !activated.Success {
		t.Fatalf("ActivateRecovered(sentry) = %+v", activated)
	}
	if _, err := os.Stat(keys.SentryCredentialFilePath(paths, auth.DefaultIdentityID, componentKey)); err != nil {
		t.Fatalf("active sentry credential stat error = %v", err)
	}
	env, ok, err := keys.ReadWitnessPublicMetadata(paths, auth.DefaultIdentityID, componentKey)
	if err != nil {
		t.Fatalf("ReadWitnessPublicMetadata() error = %v", err)
	}
	if !ok || env.WitnessKeyID != componentKey {
		t.Fatalf("witness metadata = %+v, ok %v, want component %s", env, ok, componentKey)
	}
}

func TestActivateRecoveredRollsBackWhenReloadFails(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath, address := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	service := Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})
	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	review := service.ReviewRecovered(ir, recoverResult.RestoreID)
	ir.SetReloadFunc(func(string, []byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		if reloads.Add(1) == 1 {
			return nil, errors.New("injected activation reload failure")
		}
		return &signertemplates.ReloadReport{}, nil
	})

	result := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:                   recoverResult.RestoreID,
		ReviewToken:                 review.ReviewToken,
		AcknowledgePolicyTransition: true,
	})
	if result.Code != protocol.ResultCodeRecoveredActivationFailed ||
		!strings.Contains(result.Error, "prior state was restored") {
		t.Fatalf("ActivateRecovered() = %+v, want restored failure", result)
	}
	if _, err := os.Stat(keys.AccountKeyFilePath(paths, auth.DefaultIdentityID, address)); !os.IsNotExist(err) {
		t.Fatalf("rolled-back active key stat error = %v, want not found", err)
	}
	if _, err := os.Stat(paths.RecoveredActivationDir(auth.DefaultIdentityID, recoverResult.RestoreID)); !os.IsNotExist(err) {
		t.Fatalf("activation marker stat error = %v, want not found", err)
	}
	if _, err := os.Stat(paths.RecoveredBatchDir(auth.DefaultIdentityID, recoverResult.RestoreID)); err != nil {
		t.Fatalf("recovered batch after rollback stat error = %v", err)
	}
	if got := reloads.Load(); got != 2 {
		t.Fatalf("reload count = %d, want failed activation plus rollback reload", got)
	}
}

func TestActivateRecoveredRequiresExplicitConflictReplacement(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath, address := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	service := Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})
	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if err := os.MkdirAll(paths.KeysDir(auth.DefaultIdentityID), 0o750); err != nil {
		t.Fatalf("MkdirAll(keys) error = %v", err)
	}
	activePath := keys.AccountKeyFilePath(paths, auth.DefaultIdentityID, address)
	original := []byte("prior encrypted credential")
	if err := os.WriteFile(activePath, original, 0o600); err != nil {
		t.Fatalf("WriteFile(active conflict) error = %v", err)
	}
	review := service.ReviewRecovered(ir, recoverResult.RestoreID)
	if len(review.ActiveConflicts) != 1 {
		t.Fatalf("ReviewRecovered().ActiveConflicts = %+v, want one", review.ActiveConflicts)
	}

	rejected := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:                   recoverResult.RestoreID,
		ReviewToken:                 review.ReviewToken,
		AcknowledgePolicyTransition: true,
	})
	if rejected.Code != protocol.ResultCodeActivationConflict {
		t.Fatalf("ActivateRecovered(no replace).Code = %q", rejected.Code)
	}
	got, err := os.ReadFile(activePath)
	if err != nil || string(got) != string(original) {
		t.Fatalf("active conflict after rejection = %q, %v", got, err)
	}

	activated := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:                   recoverResult.RestoreID,
		ReviewToken:                 review.ReviewToken,
		AcknowledgePolicyTransition: true,
		ReplaceExisting:             true,
	})
	if !activated.Success {
		t.Fatalf("ActivateRecovered(replace) = %+v", activated)
	}
	got, err = os.ReadFile(activePath)
	if err != nil || string(got) == string(original) {
		t.Fatalf("active credential was not replaced: bytes=%q error=%v", got, err)
	}
}

func TestActivateRecoveredCrashBoundariesResumeFromKnownState(t *testing.T) {
	tests := []struct {
		name              string
		interruptAt       activationPoint
		wantAppliedBefore int
	}{
		{
			name:              "journal published before first active write",
			interruptAt:       activationBeforeApply,
			wantAppliedBefore: 0,
		},
		{
			name:              "between active entry writes",
			interruptAt:       activationAfterEntry,
			wantAppliedBefore: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := storepaths.NewPaths(t.TempDir())
			archivePath, addresses := writeRecoverableManagedArchiveWithTwoKeys(
				t,
				paths,
				auth.DefaultIdentityID,
			)
			service := Service{Deps: backupServiceTestDeps{
				paths:   paths,
				limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
			}}
			var reloads atomic.Int64
			ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
			installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})
			recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
				ArchivePath:      archivePath,
				ExportPassphrase: []byte("export-passphrase"),
			})
			review := service.ReviewRecovered(ir, recoverResult.RestoreID)
			request := adminproto.ActivateRecoveredRequest{
				RestoreID:                   recoverResult.RestoreID,
				ReviewToken:                 review.ReviewToken,
				AcknowledgePolicyTransition: true,
			}
			var appliedEntries int
			service.activationHook = func(point activationPoint) error {
				switch tt.interruptAt {
				case activationBeforeApply:
					if point == activationBeforeApply {
						return errors.New("simulated journal-boundary crash")
					}
				case activationAfterEntry:
					if point == activationAfterEntry {
						appliedEntries++
						if appliedEntries == 1 {
							return errors.New("simulated partial-batch crash")
						}
					}
				}
				return nil
			}

			interrupted := service.ActivateRecovered(ir, request)
			if interrupted.Code != protocol.ResultCodeRecoveredActivationFailed {
				t.Fatalf("ActivateRecovered(interrupted) = %+v", interrupted)
			}
			for i, address := range addresses {
				_, err := os.Stat(keys.AccountKeyFilePath(paths, auth.DefaultIdentityID, address))
				if i < tt.wantAppliedBefore {
					if err != nil {
						t.Fatalf("applied key %d stat error = %v", i, err)
					}
				} else if !os.IsNotExist(err) {
					t.Fatalf("unapplied key %d stat error = %v, want not found", i, err)
				}
			}
			if _, err := os.Stat(
				paths.RecoveredActivationDir(auth.DefaultIdentityID, recoverResult.RestoreID),
			); err != nil {
				t.Fatalf("activation marker stat error = %v", err)
			}

			service.activationHook = nil
			resumed := service.ActivateRecovered(ir, request)
			if !resumed.Success || !resumed.Resumed || len(resumed.Activated) != len(addresses) {
				t.Fatalf("ActivateRecovered(resume) = %+v", resumed)
			}
			for _, address := range addresses {
				if _, err := os.Stat(
					keys.AccountKeyFilePath(paths, auth.DefaultIdentityID, address),
				); err != nil {
					t.Fatalf("resumed active key %s stat error = %v", address, err)
				}
			}
			if got := reloads.Load(); got != 2 {
				t.Fatalf("reload count = %d, want prior-state plus activated reload", got)
			}
		})
	}
}

func TestRollbackRecoveredRestoresReplacedCredentialAfterPartialActivation(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath, address := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	service := Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})
	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if err := os.MkdirAll(paths.KeysDir(auth.DefaultIdentityID), 0o750); err != nil {
		t.Fatalf("MkdirAll(keys) error = %v", err)
	}
	activePath := keys.AccountKeyFilePath(paths, auth.DefaultIdentityID, address)
	original := []byte("exact pre-activation encrypted credential")
	if err := os.WriteFile(activePath, original, 0o600); err != nil {
		t.Fatalf("WriteFile(active conflict) error = %v", err)
	}
	review := service.ReviewRecovered(ir, recoverResult.RestoreID)
	service.activationHook = func(point activationPoint) error {
		if point == activationAfterEntry {
			return errors.New("simulated crash after replacement")
		}
		return nil
	}

	interrupted := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:                   recoverResult.RestoreID,
		ReviewToken:                 review.ReviewToken,
		AcknowledgePolicyTransition: true,
		ReplaceExisting:             true,
	})
	if interrupted.Code != protocol.ResultCodeRecoveredActivationFailed {
		t.Fatalf("ActivateRecovered(interrupted replacement) = %+v", interrupted)
	}
	replaced, err := os.ReadFile(activePath)
	if err != nil || slices.Equal(replaced, original) {
		t.Fatalf("active replacement bytes = %q error = %v", replaced, err)
	}

	rolledBack := service.RollbackRecovered(ir, adminproto.RollbackRecoveredRequest{
		RestoreID: recoverResult.RestoreID,
	})
	if !rolledBack.Success {
		t.Fatalf("RollbackRecovered() = %+v", rolledBack)
	}
	restored, err := os.ReadFile(activePath)
	if err != nil || !slices.Equal(restored, original) {
		t.Fatalf("restored active bytes = %q error = %v, want exact original", restored, err)
	}
}

func TestActivateRecoveredExplicitlyResumesAfterHardInterruption(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath, address := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	service := Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})
	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	review := service.ReviewRecovered(ir, recoverResult.RestoreID)
	request := adminproto.ActivateRecoveredRequest{
		RestoreID:                   recoverResult.RestoreID,
		ReviewToken:                 review.ReviewToken,
		AcknowledgePolicyTransition: true,
	}
	service.activationHook = func(point activationPoint) error {
		if point != activationAfterApply {
			return nil
		}
		return errors.New("simulated hard interruption")
	}

	interrupted := service.ActivateRecovered(ir, request)
	if interrupted.Code != protocol.ResultCodeRecoveredActivationFailed ||
		!strings.Contains(interrupted.Error, "interrupted after active writes") {
		t.Fatalf("ActivateRecovered(interrupted) = %+v", interrupted)
	}
	if _, err := os.Stat(keys.AccountKeyFilePath(paths, auth.DefaultIdentityID, address)); err != nil {
		t.Fatalf("partially applied active key stat error = %v", err)
	}
	if _, err := os.Stat(paths.RecoveredActivationDir(auth.DefaultIdentityID, recoverResult.RestoreID)); err != nil {
		t.Fatalf("durable activation marker stat error = %v", err)
	}
	if got := reloads.Load(); got != 0 {
		t.Fatalf("reload count after interruption = %d, want 0", got)
	}
	incomplete := service.ReviewRecovered(ir, recoverResult.RestoreID)
	if !incomplete.Success ||
		incomplete.State != "activation_incomplete" ||
		incomplete.ReviewToken != review.ReviewToken ||
		!incomplete.AcknowledgePolicyTransition {
		t.Fatalf("ReviewRecovered(incomplete) = %+v", incomplete)
	}
	mismatch := request
	mismatch.ReplaceExisting = true
	rejected := service.ActivateRecovered(ir, mismatch)
	if rejected.Code != protocol.ResultCodeActivationReviewStale {
		t.Fatalf("ActivateRecovered(mismatched resume).Code = %q", rejected.Code)
	}

	service.activationHook = nil
	resumed := service.ActivateRecovered(ir, request)
	if !resumed.Success {
		t.Fatalf("ActivateRecovered(resume) = %+v", resumed)
	}
	if got := reloads.Load(); got != 2 {
		t.Fatalf("reload count = %d, want prior-state plus activated reload", got)
	}
	if _, err := os.Stat(paths.RecoveredBatchDir(auth.DefaultIdentityID, recoverResult.RestoreID)); !os.IsNotExist(err) {
		t.Fatalf("resumed batch stat error = %v, want not found", err)
	}
}

func TestRollbackRecoveredResolvesHardInterruption(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath, address := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	service := Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})
	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	review := service.ReviewRecovered(ir, recoverResult.RestoreID)
	service.activationHook = func(point activationPoint) error {
		if point != activationAfterApply {
			return nil
		}
		return errors.New("simulated hard interruption")
	}
	_ = service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:                   recoverResult.RestoreID,
		ReviewToken:                 review.ReviewToken,
		AcknowledgePolicyTransition: true,
	})

	rolledBack := service.RollbackRecovered(ir, adminproto.RollbackRecoveredRequest{
		RestoreID: recoverResult.RestoreID,
	})
	if !rolledBack.Success {
		t.Fatalf("RollbackRecovered() = %+v", rolledBack)
	}
	if _, err := os.Stat(keys.AccountKeyFilePath(paths, auth.DefaultIdentityID, address)); !os.IsNotExist(err) {
		t.Fatalf("active key after explicit rollback stat error = %v, want not found", err)
	}
	if _, err := os.Stat(paths.RecoveredActivationDir(auth.DefaultIdentityID, recoverResult.RestoreID)); !os.IsNotExist(err) {
		t.Fatalf("activation marker after explicit rollback stat error = %v, want not found", err)
	}
	if _, err := os.Stat(paths.RecoveredBatchDir(auth.DefaultIdentityID, recoverResult.RestoreID)); err != nil {
		t.Fatalf("batch after explicit rollback stat error = %v", err)
	}
	if got := reloads.Load(); got != 1 {
		t.Fatalf("reload count = %d, want 1", got)
	}
}

func TestRollbackRecoveredRetriesIdempotentlyAfterReloadFailure(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath, address := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	service := Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})
	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	review := service.ReviewRecovered(ir, recoverResult.RestoreID)
	service.activationHook = func(point activationPoint) error {
		if point != activationAfterApply {
			return nil
		}
		return errors.New("simulated hard interruption")
	}
	_ = service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:                   recoverResult.RestoreID,
		ReviewToken:                 review.ReviewToken,
		AcknowledgePolicyTransition: true,
	})
	ir.SetReloadFunc(func(string, []byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		if reloads.Add(1) == 1 {
			return nil, errors.New("simulated rollback reload failure")
		}
		return &signertemplates.ReloadReport{}, nil
	})

	first := service.RollbackRecovered(ir, adminproto.RollbackRecoveredRequest{
		RestoreID: recoverResult.RestoreID,
	})
	if first.Code != protocol.ResultCodeRecoveredRollbackFailed {
		t.Fatalf("RollbackRecovered(first) = %+v", first)
	}
	if _, err := os.Stat(keys.AccountKeyFilePath(paths, auth.DefaultIdentityID, address)); !os.IsNotExist(err) {
		t.Fatalf("active key after first rollback stat error = %v, want not found", err)
	}
	incomplete := service.ReviewRecovered(ir, recoverResult.RestoreID)
	if incomplete.State != "activation_incomplete" {
		t.Fatalf("ReviewRecovered().State = %q, want activation_incomplete", incomplete.State)
	}
	second := service.RollbackRecovered(ir, adminproto.RollbackRecoveredRequest{
		RestoreID: recoverResult.RestoreID,
	})
	if !second.Success {
		t.Fatalf("RollbackRecovered(second) = %+v", second)
	}
	if _, err := os.Stat(paths.RecoveredActivationDir(auth.DefaultIdentityID, recoverResult.RestoreID)); !os.IsNotExist(err) {
		t.Fatalf("activation marker after retry stat error = %v, want not found", err)
	}
	if got := reloads.Load(); got != 2 {
		t.Fatalf("reload count = %d, want 2", got)
	}
}

func TestPurgeRecoveredDeletesOnlyInactiveBatchAndRejectsIncompleteActivation(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath, _ := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	service := Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})
	first := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	purged := service.PurgeRecovered(ir, adminproto.PurgeRecoveredRequest{RestoreID: first.RestoreID})
	if !purged.Success {
		t.Fatalf("PurgeRecovered() = %+v", purged)
	}
	if _, err := os.Stat(paths.RecoveredBatchDir(auth.DefaultIdentityID, first.RestoreID)); !os.IsNotExist(err) {
		t.Fatalf("purged batch stat error = %v, want not found", err)
	}

	second := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	review := service.ReviewRecovered(ir, second.RestoreID)
	service.activationHook = func(point activationPoint) error {
		if point != activationAfterApply {
			return nil
		}
		return errors.New("simulated hard interruption")
	}
	_ = service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:                   second.RestoreID,
		ReviewToken:                 review.ReviewToken,
		AcknowledgePolicyTransition: true,
	})
	rejected := service.PurgeRecovered(ir, adminproto.PurgeRecoveredRequest{RestoreID: second.RestoreID})
	if rejected.Code != protocol.ResultCodePurgeRecoveredFailed ||
		!strings.Contains(rejected.Error, "incomplete activation") {
		t.Fatalf("PurgeRecovered(incomplete) = %+v", rejected)
	}
	if _, err := os.Stat(paths.RecoveredBatchDir(auth.DefaultIdentityID, second.RestoreID)); err != nil {
		t.Fatalf("incomplete batch after rejected purge stat error = %v", err)
	}
}

func writeMalformedManagedArchive(t *testing.T, paths storepaths.Paths, identityID, label string) string {
	t.Helper()

	archivePath := backup.BuildManagedArchivePath(paths, identityID, label)
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o770); err != nil {
		t.Fatalf("MkdirAll(archive dir) error = %v", err)
	}
	if err := os.WriteFile(archivePath, []byte("not a gzip archive"), 0o600); err != nil {
		t.Fatalf("WriteFile(archive) error = %v", err)
	}
	return archivePath
}

func writeRecoverableManagedArchive(t *testing.T, paths storepaths.Paths, identityID string) (string, string) {
	return writeRecoverableArchiveForRole(t, paths, identityID, noderole.RoleSigner)
}

func writeRecoverableManagedArchiveWithTwoKeys(
	t *testing.T,
	paths storepaths.Paths,
	identityID string,
) (string, []string) {
	t.Helper()

	root := t.TempDir()
	keysDir := filepath.Join(root, "apb")
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(apb) error = %v", err)
	}
	selectors := make([]string, 0, 2)
	for range 2 {
		selector, keyJSON := keystest.Ed25519KeyJSON(t)
		encrypted, err := crypto.EncryptStandalone(keyJSON, []byte("export-passphrase"))
		crypto.ZeroBytes(keyJSON)
		if err != nil {
			t.Fatalf("EncryptStandalone() error = %v", err)
		}
		if err := os.WriteFile(filepath.Join(keysDir, selector+".apb"), encrypted, 0o600); err != nil {
			t.Fatalf("WriteFile(apb) error = %v", err)
		}
		selectors = append(selectors, selector)
	}
	slices.Sort(selectors)
	if err := backup.WriteManifest(root, noderole.RoleSigner, time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatalf("WriteManifest() error = %v", err)
	}
	policyDir := filepath.Join(root, "policy")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(policy) error = %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(policyDir, "policy.yaml"),
		[]byte("reject_foreign_rekey: true\n"),
		0o600,
	); err != nil {
		t.Fatalf("WriteFile(source policy) error = %v", err)
	}
	archivePath := backup.BuildManagedArchivePath(paths, identityID, "recover-service-two-keys")
	if err := backup.CreateTarGzArchive(root, archivePath); err != nil {
		t.Fatalf("CreateTarGzArchive() error = %v", err)
	}
	return archivePath, selectors
}

func writeRecoverableSentryArchive(t *testing.T, paths storepaths.Paths, identityID string) (string, string) {
	return writeRecoverableArchiveForRole(t, paths, identityID, noderole.RoleSentry)
}

func writeRecoverableArchiveForRole(
	t *testing.T,
	paths storepaths.Paths,
	identityID string,
	role noderole.Role,
) (string, string) {
	return writeRecoverableArchive(t, paths, identityID, role, true)
}

func writeRecoverableArchiveWithoutManifest(
	t *testing.T,
	paths storepaths.Paths,
	identityID string,
	role noderole.Role,
) (string, string) {
	return writeRecoverableArchive(t, paths, identityID, role, false)
}

func writeRecoverableArchive(
	t *testing.T,
	paths storepaths.Paths,
	identityID string,
	role noderole.Role,
	withManifest bool,
) (string, string) {
	return writeRecoverableArchiveWithSourceSettings(
		t,
		paths,
		identityID,
		role,
		withManifest,
		nil,
	)
}

func writeRecoverableArchiveWithSourceSettings(
	t *testing.T,
	paths storepaths.Paths,
	identityID string,
	role noderole.Role,
	withManifest bool,
	sourceSettings []byte,
) (string, string) {
	t.Helper()

	root := t.TempDir()
	keysDir := filepath.Join(root, "apb")
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(apb) error = %v", err)
	}
	var selector string
	var keyJSON []byte
	switch role {
	case noderole.RoleSigner:
		selector, keyJSON = keystest.Ed25519KeyJSON(t)
	case noderole.RoleSentry:
		selector, keyJSON = keystest.SentryComponentFalcon1024KeyJSON(t, 0xcd)
	default:
		t.Fatalf("unsupported archive role %q", role)
	}
	defer crypto.ZeroBytes(keyJSON)
	encrypted, err := crypto.EncryptStandalone(keyJSON, []byte("export-passphrase"))
	if err != nil {
		t.Fatalf("EncryptStandalone() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, selector+".apb"), encrypted, 0o600); err != nil {
		t.Fatalf("WriteFile(apb) error = %v", err)
	}
	if withManifest {
		if err := backup.WriteManifest(root, role, time.Unix(1_700_000_000, 0)); err != nil {
			t.Fatalf("WriteManifest() error = %v", err)
		}
	}
	if sourceSettings != nil {
		if err := os.WriteFile(
			filepath.Join(root, backup.SourceSettingsFileName),
			sourceSettings,
			0o600,
		); err != nil {
			t.Fatalf("WriteFile(source settings) error = %v", err)
		}
	}
	policyDir := filepath.Join(root, "policy")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(policy) error = %v", err)
	}
	sourcePolicy := []byte("{}\n")
	if role == noderole.RoleSigner {
		sourcePolicy = []byte("reject_foreign_rekey: true\n")
	}
	if err := os.WriteFile(filepath.Join(policyDir, "policy.yaml"), sourcePolicy, 0o600); err != nil {
		t.Fatalf("WriteFile(source policy) error = %v", err)
	}
	label := "recover-service"
	if !withManifest {
		label = "recover-service-legacy"
	}
	archivePath := backup.BuildManagedArchivePath(paths, identityID, label)
	if err := backup.CreateTarGzArchive(root, archivePath); err != nil {
		t.Fatalf("CreateTarGzArchive() error = %v", err)
	}
	return archivePath, selector
}

func testUnlockedBackupIdentityRuntime(t *testing.T, paths storepaths.Paths, reloads *atomic.Int64) *identity.Runtime {
	return testUnlockedBackupIdentityRuntimeWithAutoApprove(t, paths, reloads, false)
}

func testUnlockedBackupIdentityRuntimeWithAutoApprove(
	t *testing.T,
	paths storepaths.Paths,
	reloads *atomic.Int64,
	userAutoApprove bool,
) *identity.Runtime {
	return testUnlockedBackupIdentityRuntimeForRole(
		t,
		paths,
		reloads,
		noderole.RoleSigner,
		userAutoApprove,
	)
}

func testUnlockedBackupIdentityRuntimeForRole(
	t *testing.T,
	paths storepaths.Paths,
	reloads *atomic.Int64,
	role noderole.Role,
	userAutoApprove bool,
) *identity.Runtime {
	t.Helper()

	if _, _, err := crypto.CreateKeystoreMetadata(paths.IdentityDir(auth.DefaultIdentityID), backupAdminTestPassphrase); err != nil {
		t.Fatalf("CreateKeystoreMetadata() error = %v", err)
	}
	keyStore := keystore.NewFileKeyStoreForPaths(paths, auth.DefaultIdentityID)
	if _, err := keyStore.InitializeMasterKey(backupAdminTestPassphrase); err != nil {
		t.Fatalf("InitializeMasterKey() error = %v", err)
	}
	ir := identity.New(identity.Config{
		ID:              auth.DefaultIdentityID,
		KeyStore:        keyStore,
		KeyPaths:        paths,
		Authenticator:   auth.NewTokenAuthenticator("token"),
		NodeRole:        role,
		UserAutoApprove: &userAutoApprove,
	})
	ir.SetReloadFunc(func(string, []byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		reloads.Add(1)
		return &signertemplates.ReloadReport{}, nil
	})
	ir.SetUnlocked()
	return ir
}

func installBackupAdminPolicy(
	t *testing.T,
	ir *identity.Runtime,
	paths storepaths.Paths,
	stored *policy.StoredConfig,
) {
	installBackupAdminPolicyForRole(t, ir, paths, stored, noderole.RoleSigner)
}

func installBackupAdminPolicyForRole(
	t *testing.T,
	ir *identity.Runtime,
	paths storepaths.Paths,
	stored *policy.StoredConfig,
	role noderole.Role,
) {
	t.Helper()
	if err := ir.WithMasterKey(func(masterKey []byte) error {
		return policy.SaveStoredConfigWithMasterKey(
			paths.Root(),
			auth.DefaultIdentityID,
			stored,
			masterKey,
			time.Unix(1_700_000_000, 0),
		)
	}); err != nil {
		t.Fatalf("SaveStoredConfigWithMasterKey() error = %v", err)
	}
	var effective *policy.Config
	var err error
	switch role {
	case noderole.RoleSigner:
		effective, err = stored.ApplySigning(nil)
	case noderole.RoleSentry:
		effective, err = stored.ApplySentry(nil)
	default:
		t.Fatalf("unsupported policy role %q", role)
	}
	if err != nil {
		t.Fatalf("apply %s policy error = %v", role, err)
	}
	ir.SetPolicyState(stored, effective)
}

func boolPointer(value bool) *bool       { return &value }
func uint64Pointer(value uint64) *uint64 { return &value }

func testBackupIdentityRuntime() *identity.Runtime {
	return identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
}

type backupServiceTestDeps struct {
	paths               storepaths.Paths
	limiter             RestoreLimiter
	genesisHashMappings map[string]string
}

func (d backupServiceTestDeps) KeyPaths() storepaths.Paths { return d.paths }
func (d backupServiceTestDeps) GenesisHashMappings() map[string]string {
	return d.genesisHashMappings
}
func (d backupServiceTestDeps) RestoreLimiter() RestoreLimiter {
	return d.limiter
}
func (d backupServiceTestDeps) WithIdentityMutation(identityID string, fn func() error) error {
	_ = identityID
	return fn()
}
func (d backupServiceTestDeps) Logf(format string, args ...interface{}) {
	_ = format
	_ = args
}

type failingBackupDeps struct {
	paths storepaths.Paths
}

func (d failingBackupDeps) KeyPaths() storepaths.Paths { return d.paths }
func (d failingBackupDeps) GenesisHashMappings() map[string]string {
	return nil
}
func (d failingBackupDeps) RestoreLimiter() RestoreLimiter {
	return nil
}
func (d failingBackupDeps) WithIdentityMutation(identityID string, fn func() error) error {
	_ = identityID
	_ = fn
	return errors.New("mutation failed")
}
func (d failingBackupDeps) Logf(format string, args ...interface{}) {
	_ = format
	_ = args
}
