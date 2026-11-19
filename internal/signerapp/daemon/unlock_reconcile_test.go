// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"errors"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/protocol"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
)

// convertTestSignerToGenerational remains as a test-call-site compatibility
// helper while all daemon fixtures are initialized directly in the atomic
// store-root layout.
func convertTestSignerToGenerational(t *testing.T, server *Signer) string {
	t.Helper()
	selection, kr, err := genstore.OpenStoreRootSelection(server.keyPaths, testPassphrase)
	if err != nil {
		t.Fatalf("OpenStoreRootSelection: %v", err)
	}
	kr.Zero()
	return selection.GenerationID()
}

func TestReconcileGenerationQuarantineRequiresAndRecordsDurableAudit(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	selection, keyring, err := genstore.OpenStoreRootSelection(server.keyPaths, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer keyring.Zero()
	current := selection.GenerationID()
	successor, err := genstore.NewGenerationID(time.Unix(1_753_800_001, 0))
	if err != nil {
		t.Fatal(err)
	}
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpRename && path == server.keyPaths.StoreRootPath() {
			return errors.New("injected pre-flip crash")
		}
		return nil
	}
	_, mintErr := genstore.Mint(server.keyPaths, genstore.MintRequest{
		SkipCandidateValidation: true,
		GenerationID:            successor,
		Parent:                  current,
		Integrity:               keyring,
		Operation:               "test-quarantine-audit",
		OperationID:             "op-" + successor,
		CreatedAt:               time.Unix(1_753_800_001, 0),
	})
	fsutil.TestHook = nil
	if mintErr == nil {
		t.Fatal("Mint succeeded despite injected pre-flip crash")
	}

	if err := server.adminServices().reconcileGenerations(server.runtime, testPassphrase); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(server.keyPaths.QuarantinedGenerationDir(successor)); err != nil {
		t.Fatalf("successor was not quarantined: %v", err)
	}
	auditBytes, err := os.ReadFile(filepath.Join(server.dataDir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	auditText := string(auditBytes)
	intent := strings.Index(auditText, "GENERATION_QUARANTINE_INTENT")
	outcome := strings.Index(auditText, "GENERATION_QUARANTINED")
	if intent < 0 || outcome < 0 || intent >= outcome {
		t.Fatalf("quarantine audit intent/outcome ordering missing: %s", auditText)
	}
	if !strings.Contains(auditText, `"generation_id":"`+successor+`"`) {
		t.Fatalf("quarantine audit missing generation ID %s: %s", successor, auditText)
	}
}

func TestUnlockFailsClosedOnMalformedGenerationContent(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	if ir == nil {
		t.Fatal("expected default product runtime")
	}
	svc := server.adminServices()
	generationID := convertTestSignerToGenerational(t, server)

	// A malformed credential inside the selected generation: structural
	// validation passes (regular file), content validation must fail closed.
	gen := server.keyPaths.GenerationPaths(generationID)
	garbage := filepath.Join(gen.KeysDir(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.key")
	if err := os.WriteFile(garbage, []byte("not-an-encrypted-credential"), 0o660); err != nil {
		t.Fatalf("WriteFile(garbage): %v", err)
	}
	ir.Lock()

	success, keyCount, errMsg, code := svc.UnlockIdentity(testPassphrase)
	if !success || keyCount != 0 || errMsg != "" || code != protocol.ResultCodeRecoveryBlocked {
		t.Fatalf("UnlockIdentity() = (%v, %d, %q, %q), want recovery entry", success, keyCount, errMsg, code)
	}
	if !ir.IsRecovery() || ir.IsUnlocked() {
		t.Fatalf("runtime state = recovery %v unlocked %v, want recovery (signing blocked)", ir.IsRecovery(), ir.IsUnlocked())
	}

	// Removing the defect and unlocking again succeeds normally.
	if err := os.Remove(garbage); err != nil {
		t.Fatalf("remove garbage: %v", err)
	}
	ir.Lock()
	success, _, errMsg, code = svc.UnlockIdentity(testPassphrase)
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
	ir := server.productRuntime()
	if ir == nil {
		t.Fatal("expected default product runtime")
	}
	svc := server.adminServices()
	generationID := convertTestSignerToGenerational(t, server)

	// A corrupt key-type state record inside the selected generation: the
	// keytypes namespace is generation content and validates fail-closed
	// exactly like keys.
	gen := server.keyPaths.GenerationPaths(generationID)
	garbage := filepath.Join(gen.KeyTypeRecordsDir(), "broken.json")
	if err := os.WriteFile(garbage, []byte("{not json"), 0o660); err != nil {
		t.Fatalf("WriteFile(garbage record): %v", err)
	}
	ir.Lock()

	success, keyCount, errMsg, code := svc.UnlockIdentity(testPassphrase)
	if !success || keyCount != 0 || errMsg != "" || code != protocol.ResultCodeRecoveryBlocked {
		t.Fatalf("UnlockIdentity() = (%v, %d, %q, %q), want recovery entry", success, keyCount, errMsg, code)
	}
	if !ir.IsRecovery() || ir.IsUnlocked() {
		t.Fatalf("runtime state = recovery %v unlocked %v, want recovery", ir.IsRecovery(), ir.IsUnlocked())
	}

	if err := os.Remove(garbage); err != nil {
		t.Fatalf("remove garbage record: %v", err)
	}
	ir.Lock()
	if success, _, errMsg, code := svc.UnlockIdentity(testPassphrase); !success || errMsg != "" || code != "" {
		t.Fatalf("UnlockIdentity(repaired) = (%v, %q, %q), want clean unlock", success, errMsg, code)
	}
}

func TestUnlockFailsClosedOnUnexpectedEntriesInGeneration(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	if ir == nil {
		t.Fatal("expected default product runtime")
	}
	svc := server.adminServices()
	generationID := convertTestSignerToGenerational(t, server)

	// Files that are neither managed credentials nor witness artifacts are
	// unaccounted-for content: strict validation treats them as defects, in
	// either namespace of the selected generation.
	gen := server.keyPaths.GenerationPaths(generationID)
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

	success, keyCount, errMsg, code := svc.UnlockIdentity(testPassphrase)
	if !success || keyCount != 0 || errMsg != "" || code != protocol.ResultCodeRecoveryBlocked {
		t.Fatalf("UnlockIdentity() = (%v, %d, %q, %q), want recovery entry", success, keyCount, errMsg, code)
	}
	if !ir.IsRecovery() || ir.IsUnlocked() {
		t.Fatalf("runtime state = recovery %v unlocked %v, want recovery", ir.IsRecovery(), ir.IsUnlocked())
	}

	for _, stray := range strays {
		if err := os.Remove(stray); err != nil {
			t.Fatalf("remove %s: %v", stray, err)
		}
	}
	ir.Lock()
	if success, _, errMsg, code := svc.UnlockIdentity(testPassphrase); !success || errMsg != "" || code != "" {
		t.Fatalf("UnlockIdentity(repaired) = (%v, %q, %q), want clean unlock", success, errMsg, code)
	}
}

// A reconcile that fails enters recovery before it releases the store
// mutation lock (RB2), not after: until then the runtime may still serve a
// generation behind the store root, and another mutation could take the lock.
func TestAFailedReconcileEntersRecoveryBeforeReleasingTheLock(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.runtime
	ir.SetUnlocked()
	ir.SetReloadFunc(func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		return nil, errors.New("simulated reload failure")
	})

	// reconcileLocked is the work reconcileReloadAndPromote runs under the
	// store mutation lock: the runtime must be in recovery when it returns,
	// before the lock around it is released.
	if _, err := server.adminServices().reconcileLocked(ir, true); err == nil {
		t.Fatal("the reconcile succeeded though its reload failed")
	}
	if !ir.IsRecovery() {
		t.Fatalf("state = %v when the locked work returned, want recovery", ir.GetState())
	}

	// Through the lock, the outcome is the same.
	ir.SetUnlocked()
	if _, err := server.adminServices().reconcileReloadAndPromote(ir, true); err == nil || !ir.IsRecovery() {
		t.Fatalf("reconcile: err = %v, state = %v; want a failure and recovery", err, ir.GetState())
	}
}

// The recovery-exit rescan after a restore or rollback leaves a lock that
// came in before it alone: a failure there keeps the signer locked rather
// than putting it back in recovery.
func TestARecoveryExitRescanKeepsALockThatCameFirst(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.runtime
	ir.SetRecovery()
	ir.Lock()
	if ir.GetState() != signerruntime.SignerStateLocked {
		t.Fatalf("state = %v after Lock, want locked", ir.GetState())
	}
	if _, ok := server.adminServices().exitRecoveryIfReconciled(ir); ok {
		t.Fatal("the rescan lifted recovery on a locked signer")
	}
	if ir.GetState() != signerruntime.SignerStateLocked {
		t.Fatalf("state = %v after the rescan, want the lock kept", ir.GetState())
	}
}
