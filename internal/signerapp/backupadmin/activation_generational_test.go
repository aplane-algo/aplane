// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// convertToGenerationalStore migrates the test store's flat layout into a
// first generation so activation exercises the pointer-commit path.
func convertToGenerationalStore(t *testing.T, paths storepaths.Paths) string {
	t.Helper()
	generationID, err := genstore.NewGenerationID(time.Unix(1_753_700_000, 0))
	if err != nil {
		t.Fatalf("NewGenerationID: %v", err)
	}
	if _, err := genstore.Mint(paths, auth.DefaultIdentityID, genstore.MintRequest{
		GenerationID:    generationID,
		FirstGeneration: true,
		Operation:       "test-init",
		OperationID:     "init-" + generationID,
		CreatedAt:       time.Unix(1_753_700_000, 0),
		Apply: func(staged storepaths.GenPaths) error {
			for _, dir := range []string{paths.KeysDir(auth.DefaultIdentityID), paths.KeyTypeRecordsDir(auth.DefaultIdentityID)} {
				entries, err := os.ReadDir(dir)
				if os.IsNotExist(err) {
					continue
				}
				if err != nil {
					return err
				}
				target := staged.KeysDir()
				if filepath.Base(dir) == "keytypes" {
					target = staged.KeyTypeRecordsDir()
				}
				for _, entry := range entries {
					data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
					if err != nil {
						return err
					}
					if err := os.WriteFile(filepath.Join(target, entry.Name()), data, 0o660); err != nil {
						return err
					}
				}
			}
			return nil
		},
	}); err != nil {
		t.Fatalf("Mint(first generation): %v", err)
	}
	for _, legacy := range []string{paths.KeysDir(auth.DefaultIdentityID), paths.KeyTypeRecordsDir(auth.DefaultIdentityID)} {
		if err := os.RemoveAll(legacy); err != nil {
			t.Fatalf("remove legacy namespace: %v", err)
		}
	}
	return generationID
}

func TestGenerationalActivationCommitsWithPointerFlip(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	service := Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})
	firstGen := convertToGenerationalStore(t, paths)

	archivePath, address := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !recoverResult.Success {
		t.Fatalf("RecoverBackup() = %+v", recoverResult)
	}
	review := service.ReviewRecovered(ir, recoverResult.RestoreID)

	activated := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:   recoverResult.RestoreID,
		ReviewToken: review.ReviewToken,
	})
	if !activated.Success {
		t.Fatalf("ActivateRecovered() = %+v", activated)
	}

	// The commit produced a new generation whose parent is sealed and valid
	// as a rollback target.
	gen, err := genstore.Resolve(paths, auth.DefaultIdentityID)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if gen.GenerationID() == firstGen {
		t.Fatal("CURRENT still names the pre-activation generation")
	}
	manifest, err := genstore.ReadManifest(gen)
	if err != nil {
		t.Fatalf("ReadManifest() error = %v", err)
	}
	if manifest.Operation != "restore-activation" || manifest.SourceRestoreID != recoverResult.RestoreID || manifest.ParentID != firstGen {
		t.Fatalf("manifest = %+v", manifest)
	}
	if err := genstore.ValidateCurrent(gen); err != nil {
		t.Fatalf("activated generation failed validation: %v", err)
	}
	parent := paths.GenerationPaths(auth.DefaultIdentityID, firstGen)
	if err := genstore.ValidateSealed(parent); err != nil {
		t.Fatalf("parent generation not sealed by activation: %v", err)
	}
	// The credential lives in the new generation; nothing was written to
	// the parent or any legacy path.
	if _, err := os.Stat(filepath.Join(gen.KeysDir(), address+".key")); err != nil {
		t.Fatalf("activated key missing from new generation: %v", err)
	}
	if _, err := os.Stat(filepath.Join(parent.KeysDir(), address+".key")); !os.IsNotExist(err) {
		t.Fatalf("activation leaked into the parent generation: %v", err)
	}
	active, err := genstore.ResolveActive(paths, auth.DefaultIdentityID)
	if err != nil {
		t.Fatalf("ResolveActive() error = %v", err)
	}
	if _, err := os.Stat(keys.AccountKeyFilePathActive(active, address)); err != nil {
		t.Fatalf("resolved key path does not reach the activated credential: %v", err)
	}
	// The batch was consumed; no Tier-1 marker machinery was involved.
	if _, err := os.Stat(paths.RecoveredBatchDir(auth.DefaultIdentityID, recoverResult.RestoreID)); !os.IsNotExist(err) {
		t.Fatalf("batch still present after generational activation: %v", err)
	}

	// Rollback: repoint CURRENT at the parent.
	rollback := service.RollbackRecovered(ir, adminproto.RollbackRecoveredRequest{RestoreID: recoverResult.RestoreID})
	if !rollback.Success {
		t.Fatalf("RollbackRecovered() = %+v", rollback)
	}
	resolved, err := genstore.Resolve(paths, auth.DefaultIdentityID)
	if err != nil || resolved.GenerationID() != firstGen {
		t.Fatalf("CURRENT after rollback = %s (%v), want %s", resolved.GenerationID(), err, firstGen)
	}
	activeAfterRollback, err := genstore.ResolveActive(paths, auth.DefaultIdentityID)
	if err != nil {
		t.Fatalf("ResolveActive(after rollback) error = %v", err)
	}
	if _, err := os.Stat(keys.AccountKeyFilePathActive(activeAfterRollback, address)); !os.IsNotExist(err) {
		t.Fatalf("rolled-back credential still resolvable: %v", err)
	}
}

func TestGenerationalActivationFailureLeavesStoreUntouched(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	service := Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})
	firstGen := convertToGenerationalStore(t, paths)

	archivePath, _ := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})

	// A stale review token fails the gate before anything is staged.
	blocked := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:   recoverResult.RestoreID,
		ReviewToken: "stale",
	})
	if blocked.Success || blocked.Code != protocol.ResultCodeActivationReviewStale {
		t.Fatalf("stale-token activation = %+v", blocked)
	}

	resolved, err := genstore.Resolve(paths, auth.DefaultIdentityID)
	if err != nil || resolved.GenerationID() != firstGen {
		t.Fatalf("CURRENT = %s (%v), want untouched %s", resolved.GenerationID(), err, firstGen)
	}
	// The batch stays inactive and reviewable; no staging residue.
	entries, err := os.ReadDir(paths.GenerationsDir(auth.DefaultIdentityID))
	if err != nil || len(entries) != 1 {
		t.Fatalf("generations after failed activation = %d (%v), want 1", len(entries), err)
	}
	if _, err := os.Stat(paths.RecoveredBatchDir(auth.DefaultIdentityID, recoverResult.RestoreID)); err != nil {
		t.Fatalf("batch missing after failed activation: %v", err)
	}
}
