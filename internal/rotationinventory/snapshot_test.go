// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotationinventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const snapshotGeneration = "gen-1785300000-cafef00d"

func TestSnapshotWriteReadPinsExactEncryptedFile(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	if err := fsutil.MkdirAll(paths.ProductDir()); err != nil {
		t.Fatalf("MkdirAll(identity) error = %v", err)
	}
	kr := cryptotest.KeyringAtTerm(t, 2, bytes.Repeat([]byte{0x82}, 32))
	snapshot := validSnapshot(t)

	var operations []fsutil.HookOp
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if path == paths.RotationSnapshotPath() ||
			path == filepath.Dir(paths.RotationSnapshotPath()) {
			operations = append(operations, op)
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })

	ref, err := WriteSnapshot(paths, snapshot, kr)
	if err != nil {
		t.Fatalf("WriteSnapshot() error = %v", err)
	}
	wantOperations := []fsutil.HookOp{fsutil.OpFileSync, fsutil.OpRename, fsutil.OpDirSync}
	if !slices.Equal(operations, wantOperations) {
		t.Fatalf("durable operations = %v, want %v", operations, wantOperations)
	}
	exact, err := os.ReadFile(paths.RotationSnapshotPath())
	if err != nil {
		t.Fatalf("ReadFile(snapshot) error = %v", err)
	}
	if err := ref.VerifyExact(exact); err != nil {
		t.Fatalf("root reference does not pin written bytes: %v", err)
	}
	opened, err := ReadReferencedSnapshot(
		paths,

		ref,
		snapshot.FromTerm,
		snapshot.ToTerm,
		kr,
	)
	if err != nil {
		t.Fatalf("ReadReferencedSnapshot() error = %v", err)
	}
	if !slices.Equal(opened.Inventory, snapshot.Inventory) ||
		opened.Rollback == nil ||
		opened.Rollback.Decision != DecisionClean {
		t.Fatalf("opened snapshot = %#v, want %#v", opened, snapshot)
	}

	exact[len(exact)-1] ^= 1
	if err := os.WriteFile(
		paths.RotationSnapshotPath(),
		exact,
		fsutil.StoreFilePerm,
	); err != nil {
		t.Fatalf("WriteFile(mutated snapshot) error = %v", err)
	}
	if _, err := ReadReferencedSnapshot(
		paths,

		ref,
		snapshot.FromTerm,
		snapshot.ToTerm,
		kr,
	); err == nil || !strings.Contains(err.Error(), "root reference") {
		t.Fatalf("ReadReferencedSnapshot(mutated) error = %v, want root-reference mismatch", err)
	}
}

func TestSnapshotRejectsWrongContextTermAndTransition(t *testing.T) {
	tests := []struct {
		name       string
		sealTerm   int64
		context    crypto.ObjectContext
		expectFrom int64
		expectTo   int64
		want       string
	}{
		{
			name:       "wrong context",
			sealTerm:   2,
			context:    crypto.RotationBaselineContext(),
			expectFrom: 1,
			expectTo:   2,
			want:       "open rotation snapshot",
		},
		{
			name:       "wrong envelope term",
			sealTerm:   1,
			context:    crypto.RotationSnapshotContext(),
			expectFrom: 1,
			expectTo:   2,
			want:       "does not match target term",
		},
		{
			name:       "wrong root transition",
			sealTerm:   2,
			context:    crypto.RotationSnapshotContext(),
			expectFrom: 2,
			expectTo:   2,
			want:       "does not match root transition",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := storepaths.NewPaths(t.TempDir())
			if err := fsutil.MkdirAll(paths.ProductDir()); err != nil {
				t.Fatalf("MkdirAll(identity) error = %v", err)
			}
			snapshot := validSnapshot(t)
			plaintext, err := MarshalSnapshot(snapshot)
			if err != nil {
				t.Fatalf("MarshalSnapshot() error = %v", err)
			}
			kr := cryptotest.KeyringAtTerm(t, tt.sealTerm, bytes.Repeat([]byte{byte(0x80 + tt.sealTerm)}, 32))
			sealed, err := kr.Seal(plaintext, tt.context)
			if err != nil {
				t.Fatalf("Seal() error = %v", err)
			}
			if err := fsutil.WriteFileDurable(paths.RotationSnapshotPath(), sealed); err != nil {
				t.Fatalf("WriteFileDurable(snapshot) error = %v", err)
			}
			ref, err := crypto.NewRotationSnapshotReference(sealed)
			if err != nil {
				t.Fatalf("NewRotationSnapshotReference() error = %v", err)
			}
			if _, err := ReadReferencedSnapshot(
				paths,

				ref,
				tt.expectFrom,
				tt.expectTo,
				kr,
			); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ReadReferencedSnapshot() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestSnapshotStrictSchemaAndCanonicalInventory(t *testing.T) {
	valid := validSnapshot(t)
	encoded, err := MarshalSnapshot(valid)
	if err != nil {
		t.Fatalf("MarshalSnapshot() error = %v", err)
	}
	if _, err := ParseSnapshot(encoded); err != nil {
		t.Fatalf("ParseSnapshot(valid) error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Snapshot) []byte
	}{
		{
			name: "missing inventory array",
			mutate: func(snapshot *Snapshot) []byte {
				snapshot.Inventory = nil
				return marshalSnapshotTest(t, snapshot)
			},
		},
		{
			name: "recursive snapshot",
			mutate: func(snapshot *Snapshot) []byte {
				snapshot.Inventory[0] = Entry{
					Path:           "identities/default/rotation.snapshot.enc",
					Kind:           KindRotationSnapshot,
					Size:           10,
					SHA256:         strings.Repeat("a", 64),
					Term:           1,
					ObjectClass:    crypto.ClassRotationSnapshot,
					ObjectSelector: "pending",
				}
				return marshalSnapshotTest(t, snapshot)
			},
		},
		{
			name: "future input term",
			mutate: func(snapshot *Snapshot) []byte {
				snapshot.Inventory[0].Term = snapshot.ToTerm
				return marshalSnapshotTest(t, snapshot)
			},
		},
		{
			name: "nonconsecutive terms",
			mutate: func(snapshot *Snapshot) []byte {
				snapshot.ToTerm++
				return marshalSnapshotTest(t, snapshot)
			},
		},
		{
			name: "invalid rollback decision",
			mutate: func(snapshot *Snapshot) []byte {
				snapshot.Rollback.Decision = "invented"
				return marshalSnapshotTest(t, snapshot)
			},
		},
		{
			name: "invalid authority digest",
			mutate: func(snapshot *Snapshot) []byte {
				snapshot.Rollback.Authority.InventorySHA256 = strings.Repeat("A", 64)
				return marshalSnapshotTest(t, snapshot)
			},
		},
		{
			name: "unpinned baseline authority",
			mutate: func(snapshot *Snapshot) []byte {
				snapshot.Rollback.Authority.Source = AuthorityRotationBaseline
				return marshalSnapshotTest(t, snapshot)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snapshot := validSnapshot(t)
			if _, err := ParseSnapshot(tt.mutate(snapshot)); err == nil {
				t.Fatal("ParseSnapshot() accepted an invalid snapshot")
			}
		})
	}

	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatalf("Unmarshal(snapshot) error = %v", err)
	}
	wire["unknown"] = true
	if _, err := ParseSnapshot(marshalSnapshotTest(t, wire)); err == nil {
		t.Fatal("ParseSnapshot() accepted an unknown field")
	}
	if _, err := ParseSnapshot(append(slices.Clone(encoded), []byte("{}")...)); err == nil {
		t.Fatal("ParseSnapshot() accepted trailing JSON")
	}
}

func TestSnapshotReadEnforcesIndependentFileCap(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	if err := fsutil.MkdirAll(paths.ProductDir()); err != nil {
		t.Fatalf("MkdirAll(identity) error = %v", err)
	}
	oversized := bytes.Repeat([]byte{'x'}, crypto.MaxRotationSnapshotBytes+1)
	if err := os.WriteFile(
		paths.RotationSnapshotPath(),
		oversized,
		fsutil.StoreFilePerm,
	); err != nil {
		t.Fatalf("WriteFile(oversized snapshot) error = %v", err)
	}
	kr := cryptotest.KeyringAtTerm(t, 2, bytes.Repeat([]byte{0x82}, 32))
	ref := crypto.RotationSnapshotReference{SHA256: strings.Repeat("a", 64), Size: 1}
	if _, err := ReadReferencedSnapshot(paths, ref, 1, 2, kr); err == nil ||
		!strings.Contains(err.Error(), "size limit") {
		t.Fatalf("ReadReferencedSnapshot(oversized) error = %v, want size limit", err)
	}
}

func TestWriteSnapshotReportsDurabilityFailure(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	if err := fsutil.MkdirAll(paths.ProductDir()); err != nil {
		t.Fatalf("MkdirAll(identity) error = %v", err)
	}
	kr := cryptotest.KeyringAtTerm(t, 2, bytes.Repeat([]byte{0x82}, 32))
	injected := errors.New("injected snapshot rename failure")
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpRename && path == paths.RotationSnapshotPath() {
			return injected
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })
	if _, err := WriteSnapshot(paths, validSnapshot(t), kr); !errors.Is(err, injected) {
		t.Fatalf("WriteSnapshot() error = %v, want injected durability error", err)
	}
	if _, err := os.Stat(paths.RotationSnapshotPath()); !os.IsNotExist(err) {
		t.Fatalf("snapshot exists after pre-rename failure: %v", err)
	}
}

func marshalSnapshotTest(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return data
}

func validSnapshot(t *testing.T) *Snapshot {
	t.Helper()
	manifest := &genstore.Manifest{
		Inventory: []genstore.InventoryEntry{{
			Path:   "keys/ACCOUNT.key",
			SHA256: strings.Repeat("1", 64),
			Size:   100,
		}},
	}
	authority, err := ManifestAuthority(manifest)
	if err != nil {
		t.Fatalf("ManifestAuthority() error = %v", err)
	}
	report := &Report{
		CurrentGeneration: snapshotGeneration,
		Entries: []Entry{
			{
				Path:           "identities/default/generations/" + snapshotGeneration + "/keys/ACCOUNT.key",
				Kind:           KindAccountKey,
				Size:           100,
				SHA256:         strings.Repeat("1", 64),
				Term:           1,
				ObjectClass:    crypto.ClassAccountKey,
				ObjectSelector: "ACCOUNT",
			},
			{
				Path:   "identities/default/generations/" + snapshotGeneration + "/manifest.json",
				Kind:   KindGenerationManifest,
				Size:   200,
				SHA256: strings.Repeat("4", 64),
			},
			{
				Path:   "identities/default/policy.yaml",
				Kind:   KindPolicyDocument,
				Size:   50,
				SHA256: strings.Repeat("2", 64),
			},
			{
				Path:   "identities/default/policy.yaml.hmac",
				Kind:   KindPolicySidecar,
				Size:   80,
				SHA256: strings.Repeat("3", 64),
				Term:   1,
			},
		},
	}
	snapshot, err := NewSnapshot(report, 1, 2, &RollbackCutover{
		GenerationID: snapshotGeneration,
		Decision:     DecisionClean,
		Authority:    authority,
	})
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	return snapshot
}
