// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotationinventory

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
)

func TestStartRotationCommitsSnapshotAnchorsAndRootInOrder(t *testing.T) {
	fixture := newInventoryFixture(t)
	t.Cleanup(fixture.kr.Zero)
	passphrase := []byte("rotation-integration-passphrase")
	prepareInventoryFixtureKeyringStore(t, fixture, passphrase)
	if err := fsutil.RemoveDurable(
		fixture.paths.RotationSnapshotPath(inventoryIdentity),
	); err != nil {
		t.Fatalf("RemoveDurable(snapshot) error = %v", err)
	}
	if err := fsutil.RemoveDurable(
		fixture.paths.RotationBaselinePath(inventoryIdentity),
	); err != nil {
		t.Fatalf("RemoveDurable(baseline) error = %v", err)
	}

	type operation struct {
		op   fsutil.HookOp
		path string
	}
	var operations []operation
	snapshotPath := fixture.paths.RotationSnapshotPath(inventoryIdentity)
	rootPath := crypto.KeyringPath(fixture.paths.IdentityDir(inventoryIdentity))
	identityDir := fixture.paths.IdentityDir(inventoryIdentity)
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if path == snapshotPath || path == rootPath || path == identityDir {
			operations = append(operations, operation{op: op, path: path})
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })

	snapshot, err := StartRotation(
		fixture.paths,
		inventoryIdentity,
		fixture.kr,
		passphrase,
	)
	if err != nil {
		t.Fatalf("StartRotation() error = %v", err)
	}
	wantOperations := []operation{
		{op: fsutil.OpFileSync, path: snapshotPath},
		{op: fsutil.OpRename, path: snapshotPath},
		{op: fsutil.OpDirSync, path: identityDir},
		{op: fsutil.OpFileSync, path: rootPath},
		{op: fsutil.OpRename, path: rootPath},
		{op: fsutil.OpDirSync, path: identityDir},
	}
	if !slices.Equal(operations, wantOperations) {
		t.Fatalf("durable operation order = %#v, want %#v", operations, wantOperations)
	}
	if snapshot == nil || snapshot.FromTerm != 1 || snapshot.ToTerm != 2 {
		t.Fatalf("StartRotation() snapshot = %#v", snapshot)
	}
	if snapshot.Rollback != nil {
		t.Fatalf("non-activation current generation got rollback metadata: %#v", snapshot.Rollback)
	}
	state, pending := fixture.kr.PendingRotation()
	if !pending || state.FromTerm != 1 || state.ToTerm != 2 {
		t.Fatalf("PendingRotation() = (%#v, %v)", state, pending)
	}
	opened, err := ReadReferencedSnapshot(
		fixture.paths,
		inventoryIdentity,
		state.Snapshot,
		state.FromTerm,
		state.ToTerm,
		fixture.kr,
	)
	if err != nil {
		t.Fatalf("ReadReferencedSnapshot() error = %v", err)
	}
	if !slices.Equal(opened.Inventory, snapshot.Inventory) {
		t.Fatal("root-referenced snapshot does not match the committed cutover")
	}
	anchor, ok := fixture.kr.HistoricalGenerationAnchor(inventoryGenA)
	if !ok {
		t.Fatalf("pending root omitted retained generation %s", inventoryGenA)
	}
	if err := genstore.ValidateAnchoredSealed(
		fixture.paths.GenerationPaths(inventoryIdentity, inventoryGenA),
		anchor,
		fixture.kr,
	); err != nil {
		t.Fatalf("ValidateAnchoredSealed() error = %v", err)
	}
	if _, ok := fixture.kr.HistoricalGenerationAnchor(inventoryGenB); ok {
		t.Fatal("pending root anchored the mutable current generation")
	}
	if _, err := Scan(fixture.paths, inventoryIdentity, fixture.kr); err != nil {
		t.Fatalf("Scan(pending anchored store) error = %v", err)
	}

	operations = nil
	if _, err := StartRotation(
		fixture.paths,
		inventoryIdentity,
		fixture.kr,
		passphrase,
	); !errors.Is(err, crypto.ErrRotationAlreadyPending) {
		t.Fatalf("StartRotation(second) error = %v, want R5 guard", err)
	}
	if len(operations) != 0 {
		t.Fatalf("R5 guard performed durable operations: %#v", operations)
	}

	reopened, err := crypto.OpenKeyringStore(identityDir, passphrase)
	if err != nil {
		t.Fatalf("OpenKeyringStore() error = %v", err)
	}
	defer reopened.Zero()
	if reopenedState, ok := reopened.PendingRotation(); !ok || reopenedState != state {
		t.Fatalf("reopened pending state = (%#v, %v), want %#v", reopenedState, ok, state)
	}
}

func TestStartRotationPinsPriorBaselineAsEffectiveAuthority(t *testing.T) {
	fixture := newInventoryFixture(t)
	t.Cleanup(fixture.kr.Zero)
	passphrase := []byte("rotation-baseline-integration")
	prepareInventoryFixtureKeyringStore(t, fixture, passphrase)
	if err := fsutil.RemoveDurable(
		fixture.paths.RotationSnapshotPath(inventoryIdentity),
	); err != nil {
		t.Fatalf("RemoveDurable(snapshot) error = %v", err)
	}

	gen := fixture.paths.GenerationPaths(inventoryIdentity, inventoryGenB)
	manifest, err := genstore.ReadManifest(gen)
	if err != nil {
		t.Fatalf("ReadManifest() error = %v", err)
	}
	manifest.Operation = genstore.OperationCredentialRestore
	manifest.RestoreArchiveSHA256 = strings.Repeat("a", 64)
	manifest.RestoreRollbackEligible = true
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent(manifest) error = %v", err)
	}
	if err := fsutil.WriteFileDurable(gen.ManifestPath(), manifestBytes); err != nil {
		t.Fatalf("WriteFileDurable(manifest) error = %v", err)
	}

	snapshot, err := StartRotation(
		fixture.paths,
		inventoryIdentity,
		fixture.kr,
		passphrase,
	)
	if err != nil {
		t.Fatalf("StartRotation() error = %v", err)
	}
	if snapshot.Rollback == nil {
		t.Fatal("rollback-eligible current generation omitted cutover decision")
	}
	if snapshot.Rollback.GenerationID != inventoryGenB ||
		snapshot.Rollback.Decision != DecisionClean ||
		snapshot.Rollback.Authority.Source != AuthorityRotationBaseline {
		t.Fatalf("rollback cutover = %#v", snapshot.Rollback)
	}
	if !slices.ContainsFunc(snapshot.Inventory, func(entry Entry) bool {
		return entry.Kind == KindRotationBaseline
	}) {
		t.Fatal("snapshot omitted the prior baseline exact-file input")
	}
}

func prepareInventoryFixtureKeyringStore(
	t *testing.T,
	fixture inventoryFixture,
	passphrase []byte,
) {
	t.Helper()
	identityDir := fixture.paths.IdentityDir(inventoryIdentity)
	for _, path := range []string{
		crypto.KeyringPath(identityDir),
		filepath.Join(identityDir, ".keystore"),
	} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Fatalf("remove fixture placeholder %s: %v", path, err)
		}
	}
	created, err := crypto.CreateKeyringStore(identityDir, passphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	created.Zero()
	if err := crypto.WriteKeyring(identityDir, fixture.kr, passphrase); err != nil {
		t.Fatalf("WriteKeyring(fixture) error = %v", err)
	}
}
