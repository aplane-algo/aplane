// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/asasetstore"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/noderole"
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
		SkipCandidateValidation: true,
		GenerationID:            genA, FirstGeneration: true,
		InitialPassphrase: passphrase, Integrity: kr, Operation: "test-init",
		OperationID: "init-a", CreatedAt: time.Unix(1_785_300_000, 0),
		Apply: func(staged storepaths.GenPaths) error {
			if err := genstoretest.ApplyAuthorityPlaceholders(staged); err != nil {
				return err
			}
			if err := fsutil.WriteFileDurable(filepath.Join(staged.KeysDir(), "ACCOUNT.key"), originalEnvelope); err != nil {
				return err
			}
			return fsutil.WriteFileDurable(filepath.Join(staged.KeyTypeRecordsDir(), "state.json"), []byte(`{"enabled":true}`))
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
		SkipCandidateValidation: true,
		GenerationID:            genB, Parent: first.GenerationID(),
		Operation: genstore.OperationCredentialRestore, OperationID: "restore-b",
		CreatedAt: time.Unix(1_785_300_001, 0), Integrity: kr,
		Apply: func(staged storepaths.GenPaths) error {
			if err := fsutil.WriteFileDurable(filepath.Join(staged.KeysDir(), "ACCOUNT.key"), newerEnvelope); err != nil {
				return err
			}
			return fsutil.WriteFileDurable(filepath.Join(staged.DeletedKeyTypeRecordsDir(), "keep.json"), []byte("monotonic-delete"))
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
		SkipCandidateValidation: true,
		GenerationID:            genC, Parent: second.GenerationID(),
		Operation: genstore.OperationCredentialRestoreRollback, OperationID: "rollback-c",
		CreatedAt: time.Unix(1_785_300_002, 0), Integrity: kr,
		Apply: func(staged storepaths.GenPaths) error {
			return populateRollbackGeneration(source, noderole.RoleSigner, staged, kr)
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

// Rollback reconstructs only keys/ and keytypes/ through
// rollbackMemberContext; the outgoing generation keeps everything else, so
// the classifier refuses any other member rather than rewrite it.
func TestRollbackMemberContextRefusesWhatTheOutgoingGenerationKeeps(t *testing.T) {
	for _, path := range []string{
		storepaths.ASASetFileName, storepaths.ASASetFileName + ".hmac",
		storepaths.DefaultPolicyFileName, storepaths.NodeRoleSidecarName,
		"policies/ACCOUNT.json", "deleted/keys/ACCOUNT.key",
	} {
		_, _, err := rollbackMemberContext(genstore.InventoryEntry{Path: path})
		if err == nil || !strings.Contains(err.Error(), "unsupported inventory member") {
			t.Fatalf("rollbackMemberContext(%s) error = %v, want an unsupported member", path, err)
		}
	}
	if _, sealed, err := rollbackMemberContext(genstore.InventoryEntry{Path: "keytypes/example.v1.json"}); err != nil || sealed {
		t.Fatalf("rollbackMemberContext(key type state) = sealed %v, %v; want plaintext", sealed, err)
	}
}

// Rollback keeps the outgoing generation's ASA set, not the source's, even
// when both are non-empty and differ.
func TestRollbackKeepsTheOutgoingASASet(t *testing.T) {
	const (
		genA = "gen-1785300000-cafef00d"
		genB = "gen-1785300001-deadbeef"
		genC = "gen-1785300002-feedface"
	)
	paths := storepaths.NewPaths(t.TempDir())
	kr, err := crypto.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	sourceSet := asaSetForRestoreTest(t, 7, "SOURCE")
	outgoingSet := asaSetForRestoreTest(t, 8, "OUTGO")
	first, err := genstore.Mint(paths, genstore.MintRequest{
		SkipCandidateValidation: true,
		GenerationID:            genA, FirstGeneration: true,
		InitialPassphrase: []byte("rollback-asa-passphrase"), Integrity: kr, Operation: "test-init",
		OperationID: "init-a", CreatedAt: time.Unix(1_785_300_000, 0),
		Apply: func(staged storepaths.GenPaths) error {
			if err := genstoretest.ApplyAuthorityPlaceholders(staged); err != nil {
				return err
			}
			return asasetstore.Write(staged, sourceSet, kr, time.Unix(1_785_300_000, 0))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := genstore.Mint(paths, genstore.MintRequest{
		SkipCandidateValidation: true,
		GenerationID:            genB, Parent: first.GenerationID(),
		Operation: genstore.OperationCredentialRestore, OperationID: "restore-b",
		CreatedAt: time.Unix(1_785_300_001, 0), Integrity: kr,
		Apply: func(staged storepaths.GenPaths) error {
			return asasetstore.Write(staged, outgoingSet, kr, time.Unix(1_785_300_001, 0))
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
		SkipCandidateValidation: true,
		GenerationID:            genC, Parent: second.GenerationID(),
		Operation: genstore.OperationCredentialRestoreRollback, OperationID: "rollback-c",
		CreatedAt: time.Unix(1_785_300_002, 0), Integrity: kr,
		Apply: func(staged storepaths.GenPaths) error {
			return populateRollbackGeneration(source, noderole.RoleSigner, staged, kr)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := asasetstore.Load(third, kr)
	if err != nil {
		t.Fatal(err)
	}
	if e := got.Entries(); len(e) != 1 || e[0].UnitName != "OUTGO" {
		t.Fatalf("rolled-back set = %+v, want the outgoing generation's", e)
	}
}
