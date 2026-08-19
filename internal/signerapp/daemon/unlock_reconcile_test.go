// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/rotationinventory"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// convertTestSignerToGenerational mints the store's flat namespaces into a
// first generation and removes the legacy directories.
func convertTestSignerToGenerational(t *testing.T, server *Signer) string {
	t.Helper()
	if current, err := genstore.ReadCurrent(server.keyPaths); err == nil {
		return current
	}
	generationID, err := genstore.NewGenerationID(time.Unix(1_753_800_000, 0))
	if err != nil {
		t.Fatalf("NewGenerationID: %v", err)
	}
	if _, err := genstore.Mint(server.keyPaths, genstore.MintRequest{
		GenerationID:    generationID,
		FirstGeneration: true,
		Operation:       "test-init",
		OperationID:     "init-" + generationID,
		CreatedAt:       time.Unix(1_753_800_000, 0),
		Apply: func(staged storepaths.GenPaths) error {
			for src, dst := range map[string]string{
				server.keyPaths.LegacyKeysDir():           staged.KeysDir(),
				server.keyPaths.LegacyKeyTypeRecordsDir(): staged.KeyTypeRecordsDir(),
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
		server.keyPaths.LegacyKeysDir(),
		server.keyPaths.LegacyKeyTypeRecordsDir(),
	} {
		if err := os.RemoveAll(legacy); err != nil {
			t.Fatalf("remove legacy namespace: %v", err)
		}
	}
	return generationID
}

func startPendingTestRotation(
	t *testing.T,
	server *Signer,
	passphrase []byte,
) *crypto.Keyring {
	t.Helper()
	convertTestSignerToGenerational(t, server)
	kr, err := crypto.OpenKeyringStore(
		server.keyPaths.KeystoreMetadataDir(),
		testPassphrase,
	)
	if err != nil {
		t.Fatalf("OpenKeyringStore: %v", err)
	}
	if _, err := rotationinventory.StartRotation(
		server.keyPaths,
		auth.DefaultIdentityID,
		kr,
		passphrase,
	); err != nil {
		kr.Zero()
		t.Fatalf("StartRotation: %v", err)
	}
	return kr
}

func TestUnlockCompletesPendingKeyRotationBeforePublishingIdentity(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productIdentityRuntime()
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}
	newPassphrase := []byte("new-unlock-passphrase")
	kr := startPendingTestRotation(t, server, newPassphrase)
	if _, pending := kr.PendingRotation(); !pending {
		t.Fatal("rotation is not pending after start")
	}
	kr.Zero()
	ir.Lock()

	success, _, errMsg, code := (signerAdminServices{signer: server}).
		UnlockIdentity(ir, newPassphrase)
	if !success || errMsg != "" || code != "" {
		t.Fatalf(
			"UnlockIdentity() = (%v, %q, %q), want normal unlock",
			success,
			errMsg,
			code,
		)
	}
	if !ir.IsUnlocked() || ir.IsRecovery() {
		t.Fatalf(
			"identity state = unlocked %v recovery %v, want ordinary unlocked",
			ir.IsUnlocked(),
			ir.IsRecovery(),
		)
	}
	settled, err := crypto.OpenKeyringStore(
		server.keyPaths.KeystoreMetadataDir(),
		newPassphrase,
	)
	if err != nil {
		t.Fatalf("OpenKeyringStore(new passphrase): %v", err)
	}
	defer settled.Zero()
	if _, pending := settled.PendingRotation(); pending {
		t.Fatal("unlock left the rotation pending")
	}
	if _, err := os.Stat(
		server.keyPaths.RotationSnapshotPath(),
	); !os.IsNotExist(err) {
		t.Fatalf("rotation snapshot still present after unlock completion: %v", err)
	}
}

func TestUnlockDiscardsPreRootRotationSnapshotUnderOldAuthority(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productIdentityRuntime()
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}
	convertTestSignerToGenerational(t, server)
	kr, err := crypto.OpenKeyringStore(
		server.keyPaths.KeystoreMetadataDir(),
		testPassphrase,
	)
	if err != nil {
		t.Fatalf("OpenKeyringStore() error = %v", err)
	}
	injected := errors.New("injected pre-root rename failure")
	rootPath := crypto.KeyringPath(
		server.keyPaths.ProductDir(),
	)
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpRename && path == rootPath {
			return injected
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })
	if _, err := rotationinventory.StartRotation(
		server.keyPaths,
		auth.DefaultIdentityID,
		kr,
		[]byte("uncommitted-new-passphrase"),
	); !errors.Is(err, injected) {
		kr.Zero()
		t.Fatalf("StartRotation() error = %v, want injected failure", err)
	}
	kr.Zero()
	fsutil.TestHook = nil
	ir.Lock()

	success, _, errMsg, code := (signerAdminServices{signer: server}).
		UnlockIdentity(ir, testPassphrase)
	if !success || errMsg != "" || code != "" {
		t.Fatalf(
			"UnlockIdentity(old authority) = (%v, %q, %q), want normal unlock",
			success,
			errMsg,
			code,
		)
	}
	if !ir.IsUnlocked() || ir.IsRecovery() {
		t.Fatalf(
			"identity state = unlocked %v recovery %v, want ordinary unlocked",
			ir.IsUnlocked(),
			ir.IsRecovery(),
		)
	}
	if _, err := os.Stat(
		server.keyPaths.RotationSnapshotPath(),
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pre-root rotation snapshot survived unlock: %v", err)
	}
}

func TestUnlockEntersRecoveryWhenPendingRotationCannotComplete(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productIdentityRuntime()
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}
	newPassphrase := []byte("new-recovery-passphrase")
	kr := startPendingTestRotation(t, server, newPassphrase)
	kr.Zero()
	if err := os.WriteFile(
		server.keyPaths.RotationSnapshotPath(),
		[]byte("tampered snapshot"),
		0o600,
	); err != nil {
		t.Fatalf("tamper rotation snapshot: %v", err)
	}
	ir.Lock()

	success, keyCount, errMsg, code := (signerAdminServices{signer: server}).
		UnlockIdentity(ir, newPassphrase)
	if !success || keyCount != 0 || errMsg != "" ||
		code != protocol.ResultCodeRecoveryBlocked {
		t.Fatalf(
			"UnlockIdentity() = (%v, %d, %q, %q), want recovery entry",
			success,
			keyCount,
			errMsg,
			code,
		)
	}
	if !ir.IsRecovery() || ir.IsUnlocked() {
		t.Fatalf(
			"identity state = recovery %v unlocked %v, want recovery",
			ir.IsRecovery(),
			ir.IsUnlocked(),
		)
	}
}

func TestUnlockFailsClosedOnMalformedGenerationContent(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productIdentityRuntime()
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}
	svc := signerAdminServices{signer: server}
	generationID := convertTestSignerToGenerational(t, server)

	// A malformed credential inside the selected generation: structural
	// validation passes (regular file), content validation must fail closed.
	gen := server.keyPaths.GenerationPaths(generationID)
	garbage := filepath.Join(gen.KeysDir(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.key")
	if err := os.WriteFile(garbage, []byte("not-an-encrypted-credential"), 0o660); err != nil {
		t.Fatalf("WriteFile(garbage): %v", err)
	}
	ir.Lock()

	success, keyCount, errMsg, code := svc.UnlockIdentity(ir, testPassphrase)
	if !success || keyCount != 0 || errMsg != "" || code != protocol.ResultCodeRecoveryBlocked {
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
	ir := server.productIdentityRuntime()
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}
	svc := signerAdminServices{signer: server}
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

	success, keyCount, errMsg, code := svc.UnlockIdentity(ir, testPassphrase)
	if !success || keyCount != 0 || errMsg != "" || code != protocol.ResultCodeRecoveryBlocked {
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
	ir := server.productIdentityRuntime()
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}
	svc := signerAdminServices{signer: server}
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

	success, keyCount, errMsg, code := svc.UnlockIdentity(ir, testPassphrase)
	if !success || keyCount != 0 || errMsg != "" || code != protocol.ResultCodeRecoveryBlocked {
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
