// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/rotationinventory"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// convertToGenerationalStore migrates the test store's flat layout into a
// first generation so activation exercises the pointer-commit path.
func convertToGenerationalStore(t *testing.T, paths storepaths.Paths) string {
	t.Helper()
	// Idempotent: the shared fixture already mints the first generation.
	if current, err := genstore.ReadCurrent(paths, auth.DefaultIdentityID); err == nil {
		return current
	}
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
	err = ir.WithKeyring(func(kr *crypto.Keyring) error {
		return genstore.ValidateSealed(parent, kr)
	})
	if err != nil {
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

	// Rollback: mint the parent's content into a fresh generation. The
	// content returns to the pre-activation state without rewinding the
	// generation lineage or cryptographic epoch.
	rollback := service.RollbackRecovered(ir, adminproto.RollbackRecoveredRequest{RestoreID: recoverResult.RestoreID})
	if !rollback.Success {
		t.Fatalf("RollbackRecovered() = %+v", rollback)
	}
	resolved, err := genstore.Resolve(paths, auth.DefaultIdentityID)
	if err != nil || resolved.GenerationID() == firstGen ||
		resolved.GenerationID() == gen.GenerationID() {
		t.Fatalf(
			"CURRENT after rollback = %s (%v), want a fresh generation",
			resolved.GenerationID(),
			err,
		)
	}
	rollbackManifest, err := genstore.ReadManifest(resolved)
	if err != nil {
		t.Fatalf("ReadManifest(rollback) error = %v", err)
	}
	if rollbackManifest.Operation != "restore-rollback" ||
		rollbackManifest.ParentID != gen.GenerationID() ||
		rollbackManifest.RollbackSourceGenerationID != firstGen ||
		rollbackManifest.SourceRestoreID != "" {
		t.Fatalf("rollback manifest = %+v", rollbackManifest)
	}
	activeAfterRollback, err := genstore.ResolveActive(paths, auth.DefaultIdentityID)
	if err != nil {
		t.Fatalf("ResolveActive(after rollback) error = %v", err)
	}
	if _, err := os.Stat(keys.AccountKeyFilePathActive(activeAfterRollback, address)); !os.IsNotExist(err) {
		t.Fatalf("rolled-back credential still resolvable: %v", err)
	}

	// A second rollback finds nothing to roll back: the server refused
	// before mutating anything, and the result code must say refused, not
	// failed — recovered_rollback_failed makes clients mirror a recovery
	// mode the server never entered.
	refused := service.RollbackRecovered(ir, adminproto.RollbackRecoveredRequest{RestoreID: recoverResult.RestoreID})
	if refused.Success {
		t.Fatalf("RollbackRecovered(again) = %+v, want refusal", refused)
	}
	if refused.Code != protocol.ResultCodeRecoveredRollbackRefused {
		t.Fatalf("refusal code = %q, want %q (pre-mutation refusal)", refused.Code, protocol.ResultCodeRecoveredRollbackRefused)
	}
	if ir.IsRecovery() {
		t.Fatal("pre-mutation rollback refusal put the identity into recovery")
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

// TestGenerationalActivationDurabilityUnknownEntersRecovery exercises the
// ErrCommitDurabilityUnknown branch: the CURRENT flip is visible (the
// activation IS committed for every subsequent resolution) but the directory
// sync confirming its durability failed. The handler must report failure,
// reload the visible state, and block signing in recovery mode rather than
// pretending nothing was committed.
func TestGenerationalActivationDurabilityUnknownEntersRecovery(t *testing.T) {
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
	if !recoverResult.Success {
		t.Fatalf("RecoverBackup() = %+v", recoverResult)
	}
	review := service.ReviewRecovered(ir, recoverResult.RestoreID)
	reloadsBefore := reloads.Load()

	// Fail every directory sync after the CURRENT pointer rename: the flip
	// becomes visible, but neither WriteFileDurable's parent sync nor
	// WriteCurrent's retry can confirm it survived to disk.
	var currentRenamed atomic.Bool
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpRename && filepath.Base(path) == "CURRENT" {
			currentRenamed.Store(true)
		}
		if op == fsutil.OpDirSync && currentRenamed.Load() {
			return errors.New("injected dir-sync failure")
		}
		return nil
	}
	activated := service.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{
		RestoreID:   recoverResult.RestoreID,
		ReviewToken: review.ReviewToken,
	})
	fsutil.TestHook = nil

	if !currentRenamed.Load() {
		t.Fatal("test hook never observed the CURRENT rename; the injection missed the flip")
	}
	if activated.Success {
		t.Fatalf("ActivateRecovered() = %+v, want durability-unknown failure", activated)
	}
	if activated.Code != protocol.ResultCodeRecoveredRollbackFailed {
		t.Fatalf("result code = %q, want %q", activated.Code, protocol.ResultCodeRecoveredRollbackFailed)
	}
	if !strings.Contains(activated.Error, "durability") {
		t.Fatalf("result error = %q, want durability explanation", activated.Error)
	}
	if !ir.IsRecovery() {
		t.Fatal("durability-unknown commit did not enter recovery mode")
	}
	if reloads.Load() <= reloadsBefore {
		t.Fatal("handler did not reload the visible post-flip state")
	}
	// The flip is visible and authoritative: CURRENT names the activation
	// generation, not the parent.
	gen, err := genstore.Resolve(paths, auth.DefaultIdentityID)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if gen.GenerationID() == firstGen {
		t.Fatal("CURRENT still names the pre-activation generation despite the visible flip")
	}
	manifest, err := genstore.ReadManifest(gen)
	if err != nil {
		t.Fatalf("ReadManifest() error = %v", err)
	}
	if manifest.Operation != "restore-activation" || manifest.ParentID != firstGen {
		t.Fatalf("manifest = %+v", manifest)
	}
}

// TestRollbackRefusedAfterPostActivationMutation pins the divergence guard:
// once the store is mutated after an activation (here, a key file written
// into the current generation), rolling back the restore would discard that
// unrelated later change, so the server must refuse pre-mutation with
// recovered_rollback_diverged — and accept again once the store matches the
// at-mint inventory.
func TestRollbackRefusedAfterPostActivationMutation(t *testing.T) {
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
	gen, err := genstore.Resolve(paths, auth.DefaultIdentityID)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	// Routine post-activation mutation: a new key file in the current
	// generation. It is not part of the restore.
	laterKey := filepath.Join(gen.KeysDir(), "LATERKEYADDR.key")
	if err := os.WriteFile(laterKey, []byte("post-activation credential"), 0o660); err != nil {
		t.Fatalf("write post-activation key: %v", err)
	}

	rollback := service.RollbackRecovered(ir, adminproto.RollbackRecoveredRequest{RestoreID: recoverResult.RestoreID})
	if rollback.Success {
		t.Fatalf("RollbackRecovered() = %+v, want divergence refusal", rollback)
	}
	if rollback.Code != protocol.ResultCodeRecoveredRollbackDiverged {
		t.Fatalf("refusal code = %q, want %q", rollback.Code, protocol.ResultCodeRecoveredRollbackDiverged)
	}
	if ir.IsRecovery() {
		t.Fatal("pre-mutation divergence refusal put the identity into recovery")
	}
	resolved, err := genstore.Resolve(paths, auth.DefaultIdentityID)
	if err != nil || resolved.GenerationID() != gen.GenerationID() {
		t.Fatalf("CURRENT after refusal = %s (%v), want %s unchanged", resolved.GenerationID(), err, gen.GenerationID())
	}
	if _, err := os.Stat(laterKey); err != nil {
		t.Fatalf("post-activation key disturbed by refused rollback: %v", err)
	}

	// Restore the at-mint inventory and the same rollback is accepted.
	if err := os.Remove(laterKey); err != nil {
		t.Fatalf("remove post-activation key: %v", err)
	}
	rollback = service.RollbackRecovered(ir, adminproto.RollbackRecoveredRequest{RestoreID: recoverResult.RestoreID})
	if !rollback.Success {
		t.Fatalf("RollbackRecovered(after restoring inventory) = %+v", rollback)
	}
	resolved, err = genstore.Resolve(paths, auth.DefaultIdentityID)
	if err != nil || resolved.GenerationID() == firstGen ||
		resolved.GenerationID() == gen.GenerationID() {
		t.Fatalf(
			"CURRENT after rollback = %s (%v), want a fresh generation",
			resolved.GenerationID(),
			err,
		)
	}
}

func TestRollbackConsumesMatchingRotationBaselineAndRemovesItAfterMint(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	service := Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})

	archivePath, address := writeRecoverableManagedArchive(
		t,
		paths,
		auth.DefaultIdentityID,
	)
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
	current, err := genstore.Resolve(paths, auth.DefaultIdentityID)
	if err != nil {
		t.Fatalf("Resolve(activated) error = %v", err)
	}

	// Re-seal the live credential to model rotation's ciphertext rewrite,
	// then publish the authenticated post-rewrap inventory. The at-mint
	// manifest no longer matches, so only baseline consumption can keep the
	// rollback available.
	err = ir.WithKeyring(func(kr *crypto.Keyring) error {
		keyPath := filepath.Join(current.KeysDir(), address+keys.AccountKeyExtension)
		sealed, _, err := fsutil.ReadRegularFile(keyPath)
		if err != nil {
			return err
		}
		plaintext, err := kr.Open(sealed, crypto.AccountKeyContext(address))
		if err != nil {
			return err
		}
		defer crypto.ZeroBytes(plaintext)
		rewrapped, err := kr.Seal(plaintext, crypto.AccountKeyContext(address))
		if err != nil {
			return err
		}
		defer crypto.ZeroBytes(rewrapped)
		if err := fsutil.WriteFileDurable(keyPath, rewrapped); err != nil {
			return err
		}
		inventory, err := genstore.BuildInventory(current)
		if err != nil {
			return err
		}
		baseline, err := rotationinventory.NewBaseline(
			current.GenerationID(),
			inventory,
		)
		if err != nil {
			return err
		}
		return rotationinventory.WriteBaseline(
			paths,
			auth.DefaultIdentityID,
			baseline,
			kr,
		)
	})
	if err != nil {
		t.Fatalf("prepare post-rewrap baseline: %v", err)
	}

	rollback := service.RollbackRecovered(
		ir,
		adminproto.RollbackRecoveredRequest{RestoreID: recoverResult.RestoreID},
	)
	if !rollback.Success {
		t.Fatalf("RollbackRecovered() = %+v", rollback)
	}
	rolledBack, err := genstore.Resolve(paths, auth.DefaultIdentityID)
	if err != nil {
		t.Fatalf("Resolve(rollback) error = %v", err)
	}
	if rolledBack.GenerationID() == current.GenerationID() {
		t.Fatal("rollback did not mint a fresh generation")
	}
	if _, err := os.Stat(
		paths.RotationBaselinePath(auth.DefaultIdentityID),
	); !os.IsNotExist(err) {
		t.Fatalf("stale rotation baseline survived rollback mint: %v", err)
	}
	if _, err := os.Stat(
		filepath.Join(rolledBack.KeysDir(), address+keys.AccountKeyExtension),
	); !os.IsNotExist(err) {
		t.Fatalf("restored credential survived content rollback: %v", err)
	}
}

func TestRollbackBaselineCleanupFailureOccursAfterFreshGenerationCommit(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	service := Service{Deps: backupServiceTestDeps{
		paths:   paths,
		limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
	}}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths, &policy.StoredConfig{})

	archivePath, _ := writeRecoverableManagedArchive(
		t,
		paths,
		auth.DefaultIdentityID,
	)
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
	current, err := genstore.Resolve(paths, auth.DefaultIdentityID)
	if err != nil {
		t.Fatalf("Resolve(activated) error = %v", err)
	}
	err = ir.WithKeyring(func(kr *crypto.Keyring) error {
		inventory, err := genstore.BuildInventory(current)
		if err != nil {
			return err
		}
		baseline, err := rotationinventory.NewBaseline(
			current.GenerationID(),
			inventory,
		)
		if err != nil {
			return err
		}
		return rotationinventory.WriteBaseline(
			paths,
			auth.DefaultIdentityID,
			baseline,
			kr,
		)
	})
	if err != nil {
		t.Fatalf("WriteBaseline() error = %v", err)
	}

	injected := errors.New("baseline cleanup directory sync failed")
	baselinePath := paths.RotationBaselinePath(auth.DefaultIdentityID)
	injectedOnce := false
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if injectedOnce || op != fsutil.OpDirSync ||
			path != filepath.Dir(baselinePath) {
			return nil
		}
		if _, err := os.Lstat(baselinePath); os.IsNotExist(err) {
			injectedOnce = true
			return injected
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })

	rollback := service.RollbackRecovered(
		ir,
		adminproto.RollbackRecoveredRequest{RestoreID: recoverResult.RestoreID},
	)
	if rollback.Success ||
		rollback.Code != protocol.ResultCodeRecoveredRollbackFailed {
		t.Fatalf("RollbackRecovered(cleanup failure) = %+v", rollback)
	}
	if !strings.Contains(rollback.Error, injected.Error()) {
		t.Fatalf("rollback error = %q, want injected cleanup failure", rollback.Error)
	}
	if !injectedOnce {
		t.Fatal("baseline cleanup failure was not injected")
	}
	if !ir.IsRecovery() {
		t.Fatal("post-commit cleanup failure did not enter recovery")
	}
	visible, err := genstore.Resolve(paths, auth.DefaultIdentityID)
	if err != nil {
		t.Fatalf("Resolve(after cleanup failure) error = %v", err)
	}
	if visible.GenerationID() == current.GenerationID() {
		t.Fatal("baseline cleanup ran before the fresh CURRENT commit")
	}
	if _, err := os.Lstat(baselinePath); !os.IsNotExist(err) {
		t.Fatalf("failed cleanup is not visibly removed: %v", err)
	}
}
