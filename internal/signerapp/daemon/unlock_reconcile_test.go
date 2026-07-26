// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"os"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/backup/recovered"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
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
