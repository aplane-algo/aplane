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

// Rollback brings back the source's per-key token files, opened from the
// seal-verified source and sealed again, drops those the restore added, and
// keeps the outgoing node default's token file with the node default policy.
func TestRollbackRestoresPerKeySourceTokensAndKeepsTheDefaults(t *testing.T) {
	const (
		genA     = "gen-1785300000-cafef00d"
		genB     = "gen-1785300001-deadbeef"
		genC     = "gen-1785300002-feedface"
		restored = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"
		added    = "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ"
	)
	paths := storepaths.NewPaths(t.TempDir())
	kr, err := crypto.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	write := func(staged storepaths.GenPaths, selector, content string) error {
		sealed, err := kr.Seal([]byte(content), crypto.SourceTokensContext(selector))
		if err != nil {
			return err
		}
		return fsutil.WriteFileDurable(staged.SourceTokenPath(selector), sealed)
	}
	first, err := genstore.Mint(paths, genstore.MintRequest{
		SkipCandidateValidation: true,
		GenerationID:            genA, FirstGeneration: true,
		InitialPassphrase: []byte("rollback-tokens-passphrase"), Integrity: kr, Operation: "test-init",
		OperationID: "init-a", CreatedAt: time.Unix(1_785_300_000, 0),
		Apply: func(staged storepaths.GenPaths) error {
			if err := genstoretest.ApplyAuthorityPlaceholders(staged); err != nil {
				return err
			}
			if err := write(staged, restored, "source key tokens"); err != nil {
				return err
			}
			return write(staged, "default", "source default tokens")
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
			for selector, content := range map[string]string{restored: "restored key tokens", added: "added key tokens", "default": "outgoing default tokens"} {
				if err := write(staged, selector, content); err != nil {
					return err
				}
			}
			return nil
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
			return populateRollbackGeneration(source, noderole.RoleCosigner, staged, kr)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for selector, want := range map[string]string{restored: "source key tokens", "default": "outgoing default tokens"} {
		sealed, _, err := fsutil.ReadRegularFile(third.SourceTokenPath(selector))
		if err != nil {
			t.Fatal(err)
		}
		plaintext, err := kr.Open(sealed, crypto.SourceTokensContext(selector))
		if err != nil {
			t.Fatal(err)
		}
		if string(plaintext) != want {
			t.Fatalf("rolled-back tokens of %s = %q, want %q", selector, plaintext, want)
		}
		crypto.ZeroBytes(plaintext)
	}
	if _, err := os.Stat(third.SourceTokenPath(added)); !os.IsNotExist(err) {
		t.Fatalf("rollback kept the tokens of a key the restore added: %v", err)
	}
}

// Rollback reconstructs a cosigner key's token file and nothing else in
// source_tokens/: the node default's is kept from the outgoing generation.
func TestRollbackMemberContextAcceptsOnlyAKeysTokenFile(t *testing.T) {
	const key = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"
	ctx, sealed, err := rollbackMemberContext(genstore.InventoryEntry{Path: "source_tokens/" + key + ".enc", Term: 1})
	if err != nil || !sealed || ctx != crypto.SourceTokensContext(key) {
		t.Fatalf("rollbackMemberContext(key tokens) = %v, %v, %v", ctx, sealed, err)
	}
	for _, entry := range []genstore.InventoryEntry{
		{Path: "source_tokens/default.enc", Term: 1},
		{Path: "source_tokens/" + key + ".enc"},
		{Path: "source_tokens/" + key + ".json", Term: 1},
		{Path: "source_tokens/CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM.enc", Term: 1},
	} {
		if _, _, err := rollbackMemberContext(entry); err == nil {
			t.Fatalf("rollbackMemberContext(%+v) accepted it", entry)
		}
	}
}
