// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestRollbackMintReconstructsOnlyActiveAuthorityAndPreservesMonotonicState(t *testing.T) {
	const (
		genA = "gen-1785300000-cafef00d"
		genB = "gen-1785300001-deadbeef"
		genC = "gen-1785300002-feedface"
	)
	paths := storepaths.NewPaths(t.TempDir())
	passphrase := []byte("rollback-generation-passphrase")
	kr, err := crypto.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()

	ctx := crypto.AccountKeyContext("ACCOUNT")
	originalSecret := []byte("historical credential plaintext")
	originalEnvelope, err := kr.Seal(originalSecret, ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, err := genstore.Mint(paths, genstore.MintRequest{
		GenerationID: genA, FirstGeneration: true, AtomicStoreRoot: true,
		InitialPassphrase: passphrase, Integrity: kr, Operation: "test-init",
		OperationID: "init-a", CreatedAt: time.Unix(1_785_300_000, 0),
		Apply: func(staged storepaths.GenPaths) error {
			if err := genstoretest.ApplyAuthorityPlaceholders(staged); err != nil {
				return err
			}
			if err := fsutil.WriteFile(filepath.Join(staged.KeysDir(), "ACCOUNT.key"), originalEnvelope); err != nil {
				return err
			}
			return fsutil.WriteFile(filepath.Join(staged.KeyTypeRecordsDir(), "state.json"), []byte(`{"enabled":true}`))
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	newerEnvelope, err := kr.Seal([]byte("newer credential"), ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := genstore.Mint(paths, genstore.MintRequest{
		GenerationID: genB, Parent: first.GenerationID(), AtomicStoreRoot: true,
		Operation: genstore.OperationCredentialRestore, OperationID: "restore-b",
		CreatedAt: time.Unix(1_785_300_001, 0), Integrity: kr,
		Apply: func(staged storepaths.GenPaths) error {
			if err := fsutil.WriteFile(filepath.Join(staged.KeysDir(), "ACCOUNT.key"), newerEnvelope); err != nil {
				return err
			}
			return fsutil.WriteFile(filepath.Join(staged.DeletedKeyTypeRecordsDir(), "keep.json"), []byte("monotonic-delete"))
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	source, err := loadRollbackGenerationSource(first, kr)
	if err != nil {
		t.Fatal(err)
	}
	third, err := genstore.Mint(paths, genstore.MintRequest{
		GenerationID: genC, Parent: second.GenerationID(), AtomicStoreRoot: true,
		Operation: genstore.OperationCredentialRestoreRollback, OperationID: "rollback-c",
		RollbackSourceGenerationID: first.GenerationID(),
		CreatedAt:                  time.Unix(1_785_300_002, 0), Integrity: kr,
		Apply: func(staged storepaths.GenPaths) error {
			return populateRollbackGeneration(source, staged, kr)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	rolledEnvelope, _, err := fsutil.ReadRegularFile(filepath.Join(third.KeysDir(), "ACCOUNT.key"))
	if err != nil {
		t.Fatal(err)
	}
	rolledPlaintext, err := kr.Open(rolledEnvelope, ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(rolledPlaintext)
	if !bytes.Equal(rolledPlaintext, originalSecret) {
		t.Fatalf("rollback plaintext = %q, want %q", rolledPlaintext, originalSecret)
	}
	state, err := os.ReadFile(filepath.Join(third.KeyTypeRecordsDir(), "state.json"))
	if err != nil || string(state) != `{"enabled":true}` {
		t.Fatalf("rollback key-type state = %q, %v", state, err)
	}
	deleted, err := os.ReadFile(filepath.Join(third.DeletedKeyTypeRecordsDir(), "keep.json"))
	if err != nil || string(deleted) != "monotonic-delete" {
		t.Fatalf("preserved deleted state = %q, %v", deleted, err)
	}
	manifest, err := genstore.ReadManifest(third)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ParentID != second.GenerationID() || manifest.RollbackCapability != nil {
		t.Fatalf("rollback manifest = %+v", manifest)
	}
}
