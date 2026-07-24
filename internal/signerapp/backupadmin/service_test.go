// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
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
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
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

func TestRestoreBackupRecordsLimiterFailureForMalformedArchive(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath := writeMalformedManagedArchive(t, paths, auth.DefaultIdentityID, "restore")
	limiter := NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) })
	service := Service{
		Deps: backupServiceTestDeps{
			paths:   paths,
			limiter: limiter,
		},
	}
	ir := testBackupIdentityRuntime()

	result := service.RestoreBackup(ir, adminproto.RestoreBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})

	if result.Code != protocol.ResultCodePrepareRestoreFailed {
		t.Fatalf("RestoreBackup().Code = %q, want %s", result.Code, protocol.ResultCodePrepareRestoreFailed)
	}
	if retryAfter := limiter.RetryAfter(auth.DefaultIdentityID, archivePath); retryAfter == 0 {
		t.Fatal("RetryAfter() = 0, want malformed restore to record limiter failure")
	}

	limited := service.RestoreBackup(ir, adminproto.RestoreBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if limited.Code != protocol.ResultCodeRestoreRateLimited {
		t.Fatalf("second RestoreBackup().Code = %q, want %s", limited.Code, protocol.ResultCodeRestoreRateLimited)
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
	if !slices.Contains(first.UnknownSourceSettings, "source.user_auto_approve") {
		t.Fatalf("unknown source settings = %v, want source.user_auto_approve", first.UnknownSourceSettings)
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
	t.Helper()

	root := t.TempDir()
	keysDir := filepath.Join(root, "apb")
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(apb) error = %v", err)
	}
	address, keyJSON := keystest.Ed25519KeyJSON(t)
	defer crypto.ZeroBytes(keyJSON)
	encrypted, err := crypto.EncryptStandalone(keyJSON, []byte("export-passphrase"))
	if err != nil {
		t.Fatalf("EncryptStandalone() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, address+".apb"), encrypted, 0o600); err != nil {
		t.Fatalf("WriteFile(apb) error = %v", err)
	}
	if err := backup.WriteManifest(root, noderole.RoleSigner, time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatalf("WriteManifest() error = %v", err)
	}
	policyDir := filepath.Join(root, "policy")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(policy) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "policy.yaml"), []byte("reject_foreign_rekey: true\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(source policy) error = %v", err)
	}
	archivePath := backup.BuildManagedArchivePath(paths, identityID, "recover-service")
	if err := backup.CreateTarGzArchive(root, archivePath); err != nil {
		t.Fatalf("CreateTarGzArchive() error = %v", err)
	}
	return archivePath, address
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
		NodeRole:        noderole.RoleSigner,
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
	effective, err := stored.ApplySigning(nil)
	if err != nil {
		t.Fatalf("ApplySigning() error = %v", err)
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
	paths   storepaths.Paths
	limiter RestoreLimiter
}

func (d backupServiceTestDeps) KeyPaths() storepaths.Paths { return d.paths }
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
