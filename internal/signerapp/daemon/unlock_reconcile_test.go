// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/protocol"
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
		GenerationID:    successor,
		Parent:          current,
		AtomicStoreRoot: true,
		Integrity:       keyring,
		Operation:       "test-quarantine-audit",
		OperationID:     "op-" + successor,
		CreatedAt:       time.Unix(1_753_800_001, 0),
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
