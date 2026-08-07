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
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestRollbackMintReconstructsAnchoredSourceUnderCurrentTerm(t *testing.T) {
	const (
		identity = "default"
		genA     = "gen-1785300000-cafef00d"
		genB     = "gen-1785300001-deadbeef"
		genC     = "gen-1785300002-feedface"
	)
	paths := storepaths.NewPaths(t.TempDir())
	passphrase := []byte("rollback-generation-passphrase")
	kr, err := crypto.CreateKeyringStore(paths.IdentityDir(identity), passphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	t.Cleanup(kr.Zero)

	ctx := crypto.AccountKeyContext("ACCOUNT")
	secret := []byte("historical credential plaintext")
	termOneEnvelope, err := kr.Seal(secret, ctx)
	if err != nil {
		t.Fatalf("Seal(term 1) error = %v", err)
	}
	first, err := genstore.Mint(paths, identity, genstore.MintRequest{
		GenerationID:    genA,
		FirstGeneration: true,
		Operation:       "test-init",
		OperationID:     "init-a",
		CreatedAt:       time.Unix(1_785_300_000, 0),
		Apply: func(staged storepaths.GenPaths) error {
			if err := fsutil.WriteFile(
				filepath.Join(staged.KeysDir(), "ACCOUNT.key"),
				termOneEnvelope,
			); err != nil {
				return err
			}
			return fsutil.WriteFile(
				filepath.Join(staged.KeyTypeRecordsDir(), "state.json"),
				[]byte(`{"enabled":true}`),
			)
		},
	})
	if err != nil {
		t.Fatalf("Mint(first) error = %v", err)
	}
	second, err := genstore.Mint(paths, identity, genstore.MintRequest{
		GenerationID: genB,
		Parent:       first.GenerationID(),
		Operation:    genstore.OperationCredentialRestore,
		OperationID:  "activate-b",
		CreatedAt:    time.Unix(1_785_300_001, 0),
		Integrity:    kr,
	})
	if err != nil {
		t.Fatalf("Mint(second) error = %v", err)
	}
	anchor, err := genstore.BuildHistoricalAnchor(first, kr)
	if err != nil {
		t.Fatalf("BuildHistoricalAnchor() error = %v", err)
	}

	if err := crypto.StartRotation(
		paths.IdentityDir(identity),
		kr,
		passphrase,
		[]crypto.HistoricalGenerationAnchor{anchor},
		func(target *crypto.Keyring, _, _ int64) (crypto.RotationSnapshotReference, error) {
			sealed, err := target.Seal(
				[]byte("test snapshot"),
				crypto.RotationSnapshotContext(),
			)
			if err != nil {
				return crypto.RotationSnapshotReference{}, err
			}
			defer crypto.ZeroBytes(sealed)
			return crypto.NewRotationSnapshotReference(sealed)
		},
	); err != nil {
		t.Fatalf("StartRotation() error = %v", err)
	}

	// Model the current-generation part of resume before closing the window.
	currentPath := filepath.Join(second.KeysDir(), "ACCOUNT.key")
	currentEnvelope, _, err := fsutil.ReadRegularFile(currentPath)
	if err != nil {
		t.Fatalf("ReadRegularFile(current envelope) error = %v", err)
	}
	plaintext, err := kr.Open(currentEnvelope, ctx)
	if err != nil {
		t.Fatalf("Open(current retiring envelope) error = %v", err)
	}
	termTwoEnvelope, err := kr.Seal(plaintext, ctx)
	crypto.ZeroBytes(plaintext)
	if err != nil {
		t.Fatalf("Seal(term 2) error = %v", err)
	}
	if err := fsutil.WriteFileDurable(currentPath, termTwoEnvelope); err != nil {
		t.Fatalf("WriteFileDurable(current term 2) error = %v", err)
	}
	crypto.ZeroBytes(termTwoEnvelope)
	if err := crypto.CloseRotation(paths.IdentityDir(identity), kr, passphrase); err != nil {
		t.Fatalf("CloseRotation() error = %v", err)
	}

	source, err := loadRollbackGenerationSource(first, kr)
	if err != nil {
		t.Fatalf("loadRollbackGenerationSource() error = %v", err)
	}
	third, err := genstore.Mint(paths, identity, genstore.MintRequest{
		GenerationID:               genC,
		Parent:                     second.GenerationID(),
		Operation:                  genstore.OperationCredentialRestoreRollback,
		OperationID:                "rollback-c",
		RollbackSourceGenerationID: first.GenerationID(),
		CreatedAt:                  time.Unix(1_785_300_002, 0),
		Integrity:                  kr,
		StartEmpty:                 true,
		Apply: func(staged storepaths.GenPaths) error {
			return populateRollbackGeneration(source, staged, kr)
		},
	})
	if err != nil {
		t.Fatalf("Mint(rollback) error = %v", err)
	}

	rolledEnvelope, _, err := fsutil.ReadRegularFile(
		filepath.Join(third.KeysDir(), "ACCOUNT.key"),
	)
	if err != nil {
		t.Fatalf("ReadRegularFile(rollback envelope) error = %v", err)
	}
	if term, err := crypto.EnvelopeTerm(rolledEnvelope); err != nil || term != 2 {
		t.Fatalf("rollback envelope term = %d, %v, want 2", term, err)
	}
	rolledPlaintext, err := kr.Open(rolledEnvelope, ctx)
	if err != nil {
		t.Fatalf("Open(rollback envelope) error = %v", err)
	}
	defer crypto.ZeroBytes(rolledPlaintext)
	if !bytes.Equal(rolledPlaintext, secret) {
		t.Fatalf("rollback plaintext = %q, want %q", rolledPlaintext, secret)
	}
	state, err := os.ReadFile(
		filepath.Join(third.KeyTypeRecordsDir(), "state.json"),
	)
	if err != nil || string(state) != `{"enabled":true}` {
		t.Fatalf("rollback plaintext member = %q, %v", state, err)
	}
	manifest, err := genstore.ReadManifest(third)
	if err != nil {
		t.Fatalf("ReadManifest(rollback) error = %v", err)
	}
	if manifest.ParentID != second.GenerationID() ||
		manifest.RollbackSourceGenerationID != first.GenerationID() {
		t.Fatalf("rollback manifest = %+v", manifest)
	}
}
