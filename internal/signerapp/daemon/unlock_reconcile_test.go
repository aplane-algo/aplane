// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/backup/recovered"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// plantIncompleteActivation publishes a real (journal + snapshot) activation
// marker for a handcrafted batch directory while the identity still has its
// master key available.
func plantIncompleteActivation(
	t *testing.T,
	server *Signer,
	ir *identity.Runtime,
	restoreID string,
	state recovered.ActivationState,
) {
	t.Helper()
	batchDir := server.keyPaths.RecoveredBatchDir(auth.DefaultIdentityID, restoreID)
	if err := os.MkdirAll(batchDir, 0o770); err != nil {
		t.Fatalf("MkdirAll(batch) error = %v", err)
	}
	token := strings.Repeat("ab", 32)
	journal := recovered.ActivationJournal{
		RestoreID:               restoreID,
		State:                   state,
		ReviewToken:             token,
		DestinationPolicySHA256: token,
		DestinationApprovalMode: "manual",
	}
	snapshot := recovered.RollbackSnapshot{
		RestoreID: restoreID,
		Directories: []recovered.RollbackDirectory{
			{RelativePath: "keys", Existed: true, Owned: []string{}},
			{RelativePath: "keytypes", Owned: []string{}},
		},
	}
	if err := ir.WithMasterKey(func(masterKey []byte) error {
		return recovered.CreateActivation(server.keyPaths, auth.DefaultIdentityID, journal, snapshot, masterKey)
	}); err != nil {
		t.Fatalf("CreateActivation(%s) error = %v", state, err)
	}
}

func TestUnlockAutomaticallyRollsBackSingleIncompleteActivation(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}
	svc := signerAdminServices{signer: server}

	restoreID := "0123456789abcdef0123456789abcdef"
	plantIncompleteActivation(t, server, ir, restoreID, recovered.ActivationApplying)
	ir.Lock()

	success, _, errMsg, code := svc.UnlockIdentity(ir, testPassphrase)
	if !success || errMsg != "" || code != "" {
		t.Fatalf("UnlockIdentity() = (%v, %q, %q), want clean unlock after auto-rollback", success, errMsg, code)
	}
	if !ir.IsUnlocked() || ir.IsRecovery() {
		t.Fatalf("identity state = unlocked %v recovery %v, want unlocked", ir.IsUnlocked(), ir.IsRecovery())
	}
	if _, err := os.Stat(server.keyPaths.RecoveredActivationDir(auth.DefaultIdentityID, restoreID)); !os.IsNotExist(err) {
		t.Fatalf("activation marker survived auto-rollback: err = %v", err)
	}
	// The batch itself is preserved for a fresh review.
	if _, err := os.Stat(server.keyPaths.RecoveredBatchDir(auth.DefaultIdentityID, restoreID)); err != nil {
		t.Fatalf("recovered batch missing after auto-rollback: %v", err)
	}
}

func TestUnlockFinishesCompletedActivationCleanup(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}
	svc := signerAdminServices{signer: server}

	restoreID := "aaaa456789abcdef0123456789abcdef"
	plantIncompleteActivation(t, server, ir, restoreID, recovered.ActivationCompleted)
	ir.Lock()

	success, _, errMsg, code := svc.UnlockIdentity(ir, testPassphrase)
	if !success || errMsg != "" || code != "" {
		t.Fatalf("UnlockIdentity() = (%v, %q, %q), want clean unlock after cleanup", success, errMsg, code)
	}
	if !ir.IsUnlocked() || ir.IsRecovery() {
		t.Fatalf("identity state = unlocked %v recovery %v, want unlocked", ir.IsUnlocked(), ir.IsRecovery())
	}
	// Completed activation cleanup removes the whole batch.
	if _, err := os.Stat(server.keyPaths.RecoveredBatchDir(auth.DefaultIdentityID, restoreID)); !os.IsNotExist(err) {
		t.Fatalf("batch survived completed-activation cleanup: err = %v", err)
	}
}

func TestUnlockWithMultipleMarkersFailsClosedIntoRecovery(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}
	svc := signerAdminServices{signer: server}

	first := "0123456789abcdef0123456789abcdef"
	second := "ffff456789abcdef0123456789abcdef"
	plantIncompleteActivation(t, server, ir, first, recovered.ActivationApplying)
	plantIncompleteActivation(t, server, ir, second, recovered.ActivationApplying)
	ir.Lock()

	success, keyCount, errMsg, code := svc.UnlockIdentity(ir, testPassphrase)
	if !success || keyCount != 0 || errMsg != "" || code != protocol.ResultCodeActivationIncomplete {
		t.Fatalf("UnlockIdentity() = (%v, %d, %q, %q), want recovery with %s",
			success, keyCount, errMsg, code, protocol.ResultCodeActivationIncomplete)
	}
	if !ir.IsRecovery() || ir.IsUnlocked() {
		t.Fatalf("identity state = recovery %v unlocked %v, want recovery", ir.IsRecovery(), ir.IsUnlocked())
	}
	// Ordering between the two markers is ambiguous: neither may be touched.
	for _, restoreID := range []string{first, second} {
		if _, err := os.Stat(server.keyPaths.RecoveredActivationDir(auth.DefaultIdentityID, restoreID)); err != nil {
			t.Fatalf("marker %s was touched during fail-closed unlock: %v", restoreID, err)
		}
	}
}

func TestResolvingOneBatchDoesNotUnlockWhileAnotherMarkerRemains(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}
	svc := signerAdminServices{signer: server}

	first := "0123456789abcdef0123456789abcdef"
	second := "ffff456789abcdef0123456789abcdef"
	plantIncompleteActivation(t, server, ir, first, recovered.ActivationApplying)
	plantIncompleteActivation(t, server, ir, second, recovered.ActivationApplying)
	ir.Lock()

	if success, _, _, code := svc.UnlockIdentity(ir, testPassphrase); !success || code != protocol.ResultCodeActivationIncomplete {
		t.Fatalf("UnlockIdentity() success=%v code=%q, want recovery entry", success, code)
	}

	// Rolling back one batch succeeds but must not re-enable signing while
	// the other marker remains. [P1]
	result := svc.RollbackRecovered(ir, adminproto.RollbackRecoveredRequest{RestoreID: first})
	if !result.Success {
		t.Fatalf("RollbackRecovered(first) = %+v", result)
	}
	if !ir.IsRecovery() || ir.IsUnlocked() {
		t.Fatalf("identity left recovery with marker %s still present", second)
	}

	// Resolving the last marker finally unlocks.
	result = svc.RollbackRecovered(ir, adminproto.RollbackRecoveredRequest{RestoreID: second})
	if !result.Success {
		t.Fatalf("RollbackRecovered(second) = %+v", result)
	}
	if !ir.IsUnlocked() || ir.IsRecovery() {
		t.Fatalf("identity state = unlocked %v recovery %v after final resolution", ir.IsUnlocked(), ir.IsRecovery())
	}
}

// convertTestSignerToGenerational mints the store's flat namespaces into a
// first generation and removes the legacy directories.
func convertTestSignerToGenerational(t *testing.T, server *Signer) string {
	t.Helper()
	generationID, err := genstore.NewGenerationID(time.Unix(1_753_800_000, 0))
	if err != nil {
		t.Fatalf("NewGenerationID: %v", err)
	}
	if _, err := genstore.Mint(server.keyPaths, auth.DefaultIdentityID, genstore.MintRequest{
		GenerationID:    generationID,
		FirstGeneration: true,
		Operation:       "test-init",
		OperationID:     "init-" + generationID,
		CreatedAt:       time.Unix(1_753_800_000, 0),
		Apply: func(staged storepaths.GenPaths) error {
			for src, dst := range map[string]string{
				server.keyPaths.KeysDir(auth.DefaultIdentityID):           staged.KeysDir(),
				server.keyPaths.KeyTypeRecordsDir(auth.DefaultIdentityID): staged.KeyTypeRecordsDir(),
			} {
				entries, err := os.ReadDir(src)
				if os.IsNotExist(err) {
					continue
				}
				if err != nil {
					return err
				}
				for _, entry := range entries {
					data, err := os.ReadFile(filepath.Join(src, entry.Name()))
					if err != nil {
						return err
					}
					if err := os.WriteFile(filepath.Join(dst, entry.Name()), data, 0o660); err != nil {
						return err
					}
				}
			}
			return nil
		},
	}); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	for _, legacy := range []string{
		server.keyPaths.KeysDir(auth.DefaultIdentityID),
		server.keyPaths.KeyTypeRecordsDir(auth.DefaultIdentityID),
	} {
		if err := os.RemoveAll(legacy); err != nil {
			t.Fatalf("remove legacy namespace: %v", err)
		}
	}
	return generationID
}

func TestUnlockFailsClosedOnMalformedGenerationContent(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}
	svc := signerAdminServices{signer: server}
	generationID := convertTestSignerToGenerational(t, server)

	// A malformed credential inside the selected generation: structural
	// validation passes (regular file), content validation must fail closed.
	gen := server.keyPaths.GenerationPaths(auth.DefaultIdentityID, generationID)
	garbage := filepath.Join(gen.KeysDir(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.key")
	if err := os.WriteFile(garbage, []byte("not-an-encrypted-credential"), 0o660); err != nil {
		t.Fatalf("WriteFile(garbage): %v", err)
	}
	ir.Lock()

	success, keyCount, errMsg, code := svc.UnlockIdentity(ir, testPassphrase)
	if !success || keyCount != 0 || errMsg != "" || code != protocol.ResultCodeActivationIncomplete {
		t.Fatalf("UnlockIdentity() = (%v, %d, %q, %q), want recovery entry", success, keyCount, errMsg, code)
	}
	if !ir.IsRecovery() || ir.IsUnlocked() {
		t.Fatalf("identity state = recovery %v unlocked %v, want recovery (signing blocked)", ir.IsRecovery(), ir.IsUnlocked())
	}

	// Removing the defect and unlocking again succeeds normally.
	if err := os.Remove(garbage); err != nil {
		t.Fatalf("remove garbage: %v", err)
	}
	ir.Lock()
	success, _, errMsg, code = svc.UnlockIdentity(ir, testPassphrase)
	if !success || errMsg != "" || code != "" {
		t.Fatalf("UnlockIdentity(repaired) = (%v, %q, %q), want clean unlock", success, errMsg, code)
	}
	if !ir.IsUnlocked() {
		t.Fatal("identity not unlocked after repair")
	}
}

func TestUnlockFailsClosedOnMalformedKeyTypeRecord(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}
	svc := signerAdminServices{signer: server}
	generationID := convertTestSignerToGenerational(t, server)

	// A corrupt key-type state record inside the selected generation: the
	// keytypes namespace is generation content and validates fail-closed
	// exactly like keys.
	gen := server.keyPaths.GenerationPaths(auth.DefaultIdentityID, generationID)
	garbage := filepath.Join(gen.KeyTypeRecordsDir(), "broken.json")
	if err := os.WriteFile(garbage, []byte("{not json"), 0o660); err != nil {
		t.Fatalf("WriteFile(garbage record): %v", err)
	}
	ir.Lock()

	success, keyCount, errMsg, code := svc.UnlockIdentity(ir, testPassphrase)
	if !success || keyCount != 0 || errMsg != "" || code != protocol.ResultCodeActivationIncomplete {
		t.Fatalf("UnlockIdentity() = (%v, %d, %q, %q), want recovery entry", success, keyCount, errMsg, code)
	}
	if !ir.IsRecovery() || ir.IsUnlocked() {
		t.Fatalf("identity state = recovery %v unlocked %v, want recovery", ir.IsRecovery(), ir.IsUnlocked())
	}

	if err := os.Remove(garbage); err != nil {
		t.Fatalf("remove garbage record: %v", err)
	}
	ir.Lock()
	if success, _, errMsg, code := svc.UnlockIdentity(ir, testPassphrase); !success || errMsg != "" || code != "" {
		t.Fatalf("UnlockIdentity(repaired) = (%v, %q, %q), want clean unlock", success, errMsg, code)
	}
}

func TestUnlockFailsClosedOnUnexpectedEntriesInGeneration(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}
	svc := signerAdminServices{signer: server}
	generationID := convertTestSignerToGenerational(t, server)

	// Files that are neither managed credentials nor witness artifacts are
	// unaccounted-for content: strict validation treats them as defects, in
	// either namespace of the selected generation.
	gen := server.keyPaths.GenerationPaths(auth.DefaultIdentityID, generationID)
	strays := []string{
		filepath.Join(gen.KeysDir(), "notes.txt"),
		filepath.Join(gen.KeyTypeRecordsDir(), "backup.tar"),
	}
	for _, stray := range strays {
		if err := os.WriteFile(stray, []byte("stray"), 0o660); err != nil {
			t.Fatalf("WriteFile(%s): %v", stray, err)
		}
	}
	ir.Lock()

	success, keyCount, errMsg, code := svc.UnlockIdentity(ir, testPassphrase)
	if !success || keyCount != 0 || errMsg != "" || code != protocol.ResultCodeActivationIncomplete {
		t.Fatalf("UnlockIdentity() = (%v, %d, %q, %q), want recovery entry", success, keyCount, errMsg, code)
	}
	if !ir.IsRecovery() || ir.IsUnlocked() {
		t.Fatalf("identity state = recovery %v unlocked %v, want recovery", ir.IsRecovery(), ir.IsUnlocked())
	}

	for _, stray := range strays {
		if err := os.Remove(stray); err != nil {
			t.Fatalf("remove %s: %v", stray, err)
		}
	}
	ir.Lock()
	if success, _, errMsg, code := svc.UnlockIdentity(ir, testPassphrase); !success || errMsg != "" || code != "" {
		t.Fatalf("UnlockIdentity(repaired) = (%v, %q, %q), want clean unlock", success, errMsg, code)
	}
}

func TestUnlockClosesMigrationCrashWindow(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}
	svc := signerAdminServices{signer: server}
	convertTestSignerToGenerational(t, server)
	// The test store's metadata is v2, so after conversion this signer sits
	// in the migration flip-to-bump crash window: generational by pointer,
	// metadata without the layout version gate.
	metaDir := server.keyPaths.KeystoreMetadataDir(auth.DefaultIdentityID)
	if meta, err := crypto.LoadKeystoreMetadata(metaDir); err != nil || meta == nil || meta.IsGenerationalLayout() {
		t.Fatalf("precondition: metadata = %+v (%v), want pre-generational v2", meta, err)
	}
	ir.Lock()

	if success, _, errMsg, code := svc.UnlockIdentity(ir, testPassphrase); !success || errMsg != "" || code != "" {
		t.Fatalf("UnlockIdentity() = (%v, %q, %q), want clean unlock", success, errMsg, code)
	}
	meta, err := crypto.LoadKeystoreMetadata(metaDir)
	if err != nil || meta == nil || !meta.IsGenerationalLayout() {
		t.Fatalf("metadata after unlock = %+v (%v), want the layout version gate written (window closed)", meta, err)
	}
}
