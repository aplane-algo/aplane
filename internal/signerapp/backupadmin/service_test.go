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
	if err := ir.WithKeyring(func(masterKey *crypto.Keyring) error {
		encrypted, err := masterKey.Seal(keyJSON, crypto.AccountKeyContext(address))
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
	manifest, err := backup.OpenSealedManifest(extractDir, []byte("export-passphrase"))
	if err != nil {
		t.Fatalf("OpenSealedManifest() error = %v", err)
	}
	document := manifest.SourceProjection()
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
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("Marshal(source projection) error = %v", err)
	}
	for _, forbidden := range []string{"algod_token", "algod_url", "endpoint"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("source settings contain forbidden field %q: %s", forbidden, encoded)
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
	if err := ir.WithKeyring(func(masterKey *crypto.Keyring) error {
		return noderole.SaveIdentitySidecarWithKeyring(
			paths,
			auth.DefaultIdentityID,
			roleBytes,
			masterKey,
			time.Unix(1_700_000_000, 0),
		)
	}); err != nil {
		t.Fatalf("SaveIdentitySidecarWithKeyring() error = %v", err)
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
	if err := ir.KeyStore().Unlock(newPassphrase); err != nil {
		t.Fatalf("InitializeMasterKey(rotated passphrase) error = %v", err)
	}

	review := service.ReviewRecovered(ir, recoveredResult.RestoreID)
	if !review.Success {
		t.Fatalf("ReviewRecovered(after rotation) = %+v", review)
	}
	activated := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:   recoveredResult.RestoreID,
		ReviewToken: review.ReviewToken,
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
	// The archive carries no source settings, so nothing can report what the
	// source approved. The destination auto-approves, so the warning and its
	// acknowledgement are required anyway.
	if first.DestinationApprovalMode != adminproto.DestinationApprovalAutoApproveFallback ||
		first.UnattendedSigningWarning == "" ||
		!first.UnattendedSigningAckRequired {
		t.Fatalf("destination approval review = mode %q warning %q", first.DestinationApprovalMode, first.UnattendedSigningWarning)
	}
	// Policy differences are informational and never require acknowledgement.
	if first.PolicyComparison != string(policy.RestoreComparisonDifferent) ||
		len(first.SecurityChanges) == 0 ||
		first.SecurityChanges[0].Category != string(policy.RestoreCategoryHardRejects) {
		t.Fatalf("policy comparison = status %q changes %+v", first.PolicyComparison, first.SecurityChanges)
	}
	if first.SourceUserAutoApprove == nil || *first.SourceUserAutoApprove ||
		len(first.SourceGenesisHashMappings) != 0 {
		t.Fatalf("authenticated source settings review = %+v", first)
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
	if changedPolicy.PolicyComparison != string(policy.RestoreComparisonIdentical) {
		t.Fatalf("matching policy review = %+v, want identical comparison", changedPolicy)
	}
	if got := reloads.Load(); got != 0 {
		t.Fatalf("runtime reload count = %d, want 0", got)
	}
}

func TestReviewRecoveredCarriesAuthenticatedSourceSettings(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genesisHash := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 32))
	autoApprove := false
	archivePath, _ := writeRecoverableArchiveWithSourceSettings(
		t,
		paths,
		auth.DefaultIdentityID,
		noderole.RoleSigner,
		backup.SourceSettingsSnapshot{
			UserAutoApprove:     &autoApprove,
			GenesisHashMappings: map[string]string{genesisHash: "private-network"},
		},
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
		review.SourceUserAutoApprove == nil ||
		*review.SourceUserAutoApprove ||
		len(review.SourceGenesisHashMappings) != 1 ||
		review.SourceGenesisHashMappings[0].GenesisHash != genesisHash ||
		review.SourceGenesisHashMappings[0].Network != "private-network" {
		t.Fatalf("ReviewRecovered() source settings = %+v", review)
	}
	// The archive's packaging time reaches review: it is the operator's
	// only signal against substitution of an older archive sealed under the
	// same passphrase. The fixture seals its manifest at this timestamp.
	if review.ArchiveCreatedAtUnix != 1_700_000_000 {
		t.Fatalf("ArchiveCreatedAtUnix = %d, want the archive's sealed packaging time",
			review.ArchiveCreatedAtUnix)
	}
	ir.Config().SetUserAutoApprove(true)
	autoApproveReview := service.ReviewRecovered(ir, recoverResult.RestoreID)
	if autoApproveReview.DestinationApprovalMode != adminproto.DestinationApprovalAutoApproveFallback ||
		autoApproveReview.UnattendedSigningWarning == "" ||
		!autoApproveReview.UnattendedSigningAckRequired {
		t.Fatalf("destination auto-approve warning was suppressed: %+v", autoApproveReview)
	}
	missingUnattendedAck := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:   recoverResult.RestoreID,
		ReviewToken: autoApproveReview.ReviewToken,
	})
	if missingUnattendedAck.Code != protocol.ResultCodeActivationAckRequired ||
		!strings.Contains(missingUnattendedAck.Error, "unattended-signing") {
		t.Fatalf(
			"source approval claim waived destination acknowledgement: %+v",
			missingUnattendedAck,
		)
	}

	baseToken, err := recoveredReviewToken(recoveredReviewTokenInput{
		FormatVersion:           recoveredReviewFormatVersion,
		RestoreID:               recoverResult.RestoreID,
		ArchiveSHA256:           strings.Repeat("a", 64),
		SourcePolicyStatus:      string(recovered.SourcePolicyMissing),
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
		ArchiveSHA256:           strings.Repeat("c", 64),
		SourcePolicyStatus:      string(recovered.SourcePolicyMissing),
		DestinationPolicySHA256: strings.Repeat("b", 64),
		DestinationApprovalMode: string(adminproto.DestinationApprovalManualDefault),
		PolicyComparisonFormat:  recoveredReviewFormatVersion,
	})
	if err != nil {
		t.Fatalf("recoveredReviewToken(changed archive) error = %v", err)
	}
	// Source context is authenticated by the archive, whose digest the token
	// already binds; no separate source-settings term is needed.
	if changedToken == baseToken {
		t.Fatal("archive digest did not change the review token")
	}
}

// TestRecoverBackupRejectsUnauthenticatedArchive proves an archive this
// release cannot authenticate never reaches recovery: there is no
// "valid but unverified" or "invalid source settings" state to degrade into.
func TestRecoverBackupRejectsUnauthenticatedArchive(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath, _ := writeUnauthenticatedArchive(
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
	if recoverResult.Success {
		t.Fatalf("RecoverBackup() = %+v, want rejection of an unauthenticated archive", recoverResult)
	}
	if !strings.Contains(recoverResult.Error, "unsupported backup archive format") {
		t.Fatalf("RecoverBackup() error = %q, want unsupported-format rejection", recoverResult.Error)
	}
}

func TestActivateRecoveredIdenticalPolicyNeedsNoPolicyAcknowledgement(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath, address := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	service := Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{
		StoredPolicyCore: policy.StoredPolicyCore{
			RejectForeignRekey: boolPointer(true),
		},
	})
	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !recoverResult.Success {
		t.Fatalf("RecoverBackup() = %+v", recoverResult)
	}
	review := service.ReviewRecovered(ir, recoverResult.RestoreID)
	if !review.Success ||
		review.PolicyComparison != string(policy.RestoreComparisonIdentical) {
		t.Fatalf("ReviewRecovered() = %+v, want identical comparison", review)
	}
	activated := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:   recoverResult.RestoreID,
		ReviewToken: review.ReviewToken,
	})
	if !activated.Success {
		t.Fatalf("ActivateRecovered(no policy acknowledgement) = %+v", activated)
	}
	if _, err := os.Stat(keys.AccountKeyFilePath(paths, auth.DefaultIdentityID, address)); err != nil {
		t.Fatalf("active key stat error = %v", err)
	}
}

// An archive claiming the source also auto-approved must not waive the
// destination acknowledgement: authentication proves who packaged the claim,
// never that the destination may skip operator approval.
func TestActivateRecoveredSourceAutoApproveClaimDoesNotWaiveAcknowledgement(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	sourceAutoApprove := true
	sourceSettings := backup.SourceSettingsSnapshot{UserAutoApprove: &sourceAutoApprove}
	archivePath, address := writeRecoverableArchiveWithSourceSettings(
		t,
		paths,
		auth.DefaultIdentityID,
		noderole.RoleSigner,
		sourceSettings,
	)
	service := Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntimeWithAutoApprove(t, paths, &reloads, true)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{
		StoredPolicyCore: policy.StoredPolicyCore{
			RejectForeignRekey: boolPointer(true),
		},
	})
	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	review := service.ReviewRecovered(ir, recoverResult.RestoreID)
	if !review.Success ||
		review.PolicyComparison != string(policy.RestoreComparisonIdentical) ||
		!review.UnattendedSigningAckRequired ||
		review.UnattendedSigningWarning == "" {
		t.Fatalf("source auto-approve claim suppressed the destination warning: %+v", review)
	}
	missingAck := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:   recoverResult.RestoreID,
		ReviewToken: review.ReviewToken,
	})
	if missingAck.Code != protocol.ResultCodeActivationAckRequired {
		t.Fatalf("ActivateRecovered(no acknowledgement) = %+v, want acknowledgement required", missingAck)
	}
	activated := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:                    recoverResult.RestoreID,
		ReviewToken:                  review.ReviewToken,
		AcknowledgeUnattendedSigning: true,
	})
	if !activated.Success {
		t.Fatalf("ActivateRecovered(acknowledged) = %+v", activated)
	}
	if _, err := os.Stat(keys.AccountKeyFilePath(paths, auth.DefaultIdentityID, address)); err != nil {
		t.Fatalf("active key stat error = %v", err)
	}
}

func TestActivateRecoveredPolicyTighteningNeedsNoAcknowledgement(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath, address := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	service := Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{
		StoredPolicyCore: policy.StoredPolicyCore{
			RejectForeignRekey: boolPointer(true),
			MaxFeeMicroAlgos:   uint64Pointer(1_000),
		},
	})
	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	review := service.ReviewRecovered(ir, recoverResult.RestoreID)
	if !review.Success ||
		review.PolicyComparison != string(policy.RestoreComparisonDifferent) ||
		len(review.SecurityChanges) != 1 {
		t.Fatalf("tightening review = %+v, want one factual difference", review)
	}
	activated := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:   recoverResult.RestoreID,
		ReviewToken: review.ReviewToken,
	})
	if !activated.Success {
		t.Fatalf("ActivateRecovered(tightening without acknowledgement) = %+v", activated)
	}
	if _, err := os.Stat(keys.AccountKeyFilePath(paths, auth.DefaultIdentityID, address)); err != nil {
		t.Fatalf("active key stat error = %v", err)
	}
}

func TestActivateRecoveredRequiresCurrentReviewAndAcknowledgement(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	sourceAutoApprove := false
	sourceSettings := backup.SourceSettingsSnapshot{UserAutoApprove: &sourceAutoApprove}
	archivePath, address := writeRecoverableArchiveWithSourceSettings(
		t,
		paths,
		auth.DefaultIdentityID,
		noderole.RoleSigner,
		sourceSettings,
	)
	service := Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntimeWithAutoApprove(t, paths, &reloads, true)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{
		StoredPolicyCore: policy.StoredPolicyCore{
			RejectForeignRekey: boolPointer(false),
		},
	})
	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	review := service.ReviewRecovered(ir, recoverResult.RestoreID)
	if !review.Success {
		t.Fatalf("ReviewRecovered() = %+v", review)
	}
	// Policy differences are informational; only the destination's own
	// auto-approve state requires an acknowledgement.
	if !review.UnattendedSigningAckRequired {
		t.Fatalf("auto-approve destination did not require acknowledgement: %+v", review)
	}

	stale := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:                    recoverResult.RestoreID,
		ReviewToken:                  strings.Repeat("0", 64),
		AcknowledgeUnattendedSigning: true,
	})
	if stale.Code != protocol.ResultCodeActivationReviewStale {
		t.Fatalf("ActivateRecovered(stale).Code = %q, want %q", stale.Code, protocol.ResultCodeActivationReviewStale)
	}
	missingUnattendedAck := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:   recoverResult.RestoreID,
		ReviewToken: review.ReviewToken,
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
		RestoreID:   recoveredResult.RestoreID,
		ReviewToken: review.ReviewToken,
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

func writeRecoverableSentryArchive(t *testing.T, paths storepaths.Paths, identityID string) (string, string) {
	return writeRecoverableArchiveForRole(t, paths, identityID, noderole.RoleSentry)
}

func writeRecoverableArchiveForRole(
	t *testing.T,
	paths storepaths.Paths,
	identityID string,
	role noderole.Role,
) (string, string) {
	return writeRecoverableArchive(t, paths, identityID, role)
}

// writeUnauthenticatedArchive writes an archive with no sealed manifest,
// modelling material this release cannot authenticate.
func writeUnauthenticatedArchive(
	t *testing.T,
	paths storepaths.Paths,
	identityID string,
	role noderole.Role,
) (string, string) {
	return writeArchiveForRecovery(t, paths, identityID, role, false, backup.SourceSettingsSnapshot{})
}

func writeRecoverableArchive(
	t *testing.T,
	paths storepaths.Paths,
	identityID string,
	role noderole.Role,
) (string, string) {
	return writeArchiveForRecovery(t, paths, identityID, role, true, backup.SourceSettingsSnapshot{})
}

func writeRecoverableArchiveWithSourceSettings(
	t *testing.T,
	paths storepaths.Paths,
	identityID string,
	role noderole.Role,
	sourceSettings backup.SourceSettingsSnapshot,
) (string, string) {
	return writeArchiveForRecovery(t, paths, identityID, role, true, sourceSettings)
}

func writeArchiveForRecovery(
	t *testing.T,
	paths storepaths.Paths,
	identityID string,
	role noderole.Role,
	sealManifest bool,
	sourceSettings backup.SourceSettingsSnapshot,
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
	if sealManifest {
		// Sealed last: it inventories every member written above.
		if role == noderole.RoleSigner && sourceSettings.UserAutoApprove == nil {
			// Mirrors production: a signer archive always records its
			// approval default.
			value := false
			sourceSettings.UserAutoApprove = &value
		}
		if err := backup.WriteSealedManifest(
			root,
			role,
			time.Unix(1_700_000_000, 0),
			sourceSettings,
			[]byte("export-passphrase"),
		); err != nil {
			t.Fatalf("WriteSealedManifest() error = %v", err)
		}
	} else {
		label = "recover-service-unauthenticated"
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

	if _, err := crypto.CreateKeyringStore(paths.IdentityDir(auth.DefaultIdentityID), backupAdminTestPassphrase); err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	// All stores are generational in this release; mint the first
	// generation the way initialize does.
	convertToGenerationalStore(t, paths)
	keyStore := keystore.NewFileKeyStoreForPaths(paths, auth.DefaultIdentityID)
	if err := keyStore.Unlock(backupAdminTestPassphrase); err != nil {
		t.Fatalf("Unlock() error = %v", err)
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
	if err := ir.WithKeyring(func(masterKey *crypto.Keyring) error {
		return policy.SaveStoredConfigWithKeyring(
			paths.Root(),
			auth.DefaultIdentityID,
			stored,
			masterKey,
			time.Unix(1_700_000_000, 0),
		)
	}); err != nil {
		t.Fatalf("SaveStoredConfigWithKeyring() error = %v", err)
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
