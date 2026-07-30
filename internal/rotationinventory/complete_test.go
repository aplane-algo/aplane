// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotationinventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/policy"
)

func TestCompleteRotationClosesVerifiedTransition(t *testing.T) {
	fixture, snapshot, passphrase := startCompletionFixture(t, false, false, false)
	if snapshot.Rollback != nil {
		t.Fatalf("non-rollback fixture cutover = %#v", snapshot.Rollback)
	}

	report, err := CompleteRotation(
		fixture.paths,
		inventoryIdentity,
		fixture.kr,
		passphrase,
	)
	if err != nil {
		t.Fatalf("CompleteRotation() error = %v", err)
	}
	if report.Resume == nil || report.Resume.Rewrapped == 0 ||
		!report.RootClosed || !report.SnapshotRemoved ||
		report.BaselineWritten {
		t.Fatalf("CompleteRotation() report = %#v", report)
	}
	if _, pending := fixture.kr.PendingRotation(); pending {
		t.Fatal("CompleteRotation() left root pending")
	}
	if _, err := os.Stat(
		fixture.paths.RotationSnapshotPath(inventoryIdentity),
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed snapshot still exists: %v", err)
	}
	if _, err := os.Stat(
		fixture.paths.RotationBaselinePath(inventoryIdentity),
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("non-rollback completion wrote a baseline: %v", err)
	}
	if _, err := Scan(fixture.paths, inventoryIdentity, fixture.kr); err != nil {
		t.Fatalf("Scan(settled store) error = %v", err)
	}
}

func TestCompleteRotationWritesCleanCutoverBaselineBeforeClose(t *testing.T) {
	fixture, snapshot, passphrase := startCompletionFixture(t, true, false, false)
	if snapshot.Rollback == nil ||
		snapshot.Rollback.Decision != DecisionClean {
		t.Fatalf("clean fixture cutover = %#v", snapshot.Rollback)
	}

	report, err := CompleteRotation(
		fixture.paths,
		inventoryIdentity,
		fixture.kr,
		passphrase,
	)
	if err != nil {
		t.Fatalf("CompleteRotation() error = %v", err)
	}
	if !report.BaselineWritten || !report.RootClosed ||
		!report.SnapshotRemoved {
		t.Fatalf("CompleteRotation() report = %#v", report)
	}
	baseline, err := ReadBaseline(
		fixture.paths,
		inventoryIdentity,
		fixture.kr,
	)
	if err != nil {
		t.Fatalf("ReadBaseline() error = %v", err)
	}
	inventory, err := genstore.BuildInventory(
		fixture.paths.GenerationPaths(inventoryIdentity, inventoryGenB),
	)
	if err != nil {
		t.Fatalf("BuildInventory() error = %v", err)
	}
	want, err := NewBaseline(inventoryGenB, inventory)
	if err != nil {
		t.Fatalf("NewBaseline() error = %v", err)
	}
	if *baseline != *want {
		t.Fatalf("completion baseline = %#v, want %#v", baseline, want)
	}
}

func TestCompleteRotationReplacesPinnedPriorBaseline(t *testing.T) {
	fixture, snapshot, passphrase := startCompletionFixture(t, true, false, true)
	if snapshot.Rollback == nil ||
		snapshot.Rollback.Decision != DecisionClean ||
		snapshot.Rollback.Authority.Source != AuthorityRotationBaseline {
		t.Fatalf("prior-baseline fixture cutover = %#v", snapshot.Rollback)
	}
	if !slices.ContainsFunc(snapshot.Inventory, func(entry Entry) bool {
		return entry.Kind == KindRotationBaseline
	}) {
		t.Fatal("cutover snapshot omitted the prior baseline input")
	}

	report, err := CompleteRotation(
		fixture.paths,
		inventoryIdentity,
		fixture.kr,
		passphrase,
	)
	if err != nil {
		t.Fatalf("CompleteRotation() error = %v", err)
	}
	if !report.BaselineWritten || !report.RootClosed {
		t.Fatalf("CompleteRotation() report = %#v", report)
	}
	baseline, err := ReadBaseline(
		fixture.paths,
		inventoryIdentity,
		fixture.kr,
	)
	if err != nil {
		t.Fatalf("ReadBaseline() error = %v", err)
	}
	inventory, err := genstore.BuildInventory(
		fixture.paths.GenerationPaths(inventoryIdentity, inventoryGenB),
	)
	if err != nil {
		t.Fatalf("BuildInventory() error = %v", err)
	}
	want, err := NewBaseline(inventoryGenB, inventory)
	if err != nil {
		t.Fatalf("NewBaseline() error = %v", err)
	}
	if *baseline != *want {
		t.Fatalf("completion baseline = %#v, want %#v", baseline, want)
	}
}

func TestCompleteRotationDoesNotEraseCutoverDivergence(t *testing.T) {
	fixture, snapshot, passphrase := startCompletionFixture(t, true, true, false)
	if snapshot.Rollback == nil ||
		snapshot.Rollback.Decision != DecisionDiverged {
		t.Fatalf("diverged fixture cutover = %#v", snapshot.Rollback)
	}

	report, err := CompleteRotation(
		fixture.paths,
		inventoryIdentity,
		fixture.kr,
		passphrase,
	)
	if err != nil {
		t.Fatalf("CompleteRotation() error = %v", err)
	}
	if report.BaselineWritten || report.BaselineAlreadyCurrent {
		t.Fatalf("diverged completion wrote a baseline: %#v", report)
	}
	if _, err := os.Stat(
		fixture.paths.RotationBaselinePath(inventoryIdentity),
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("diverged completion baseline exists: %v", err)
	}
}

func TestCompleteRotationPublishesBaselineBeforeRootAndSnapshotCleanup(t *testing.T) {
	fixture, _, passphrase := startCompletionFixture(t, true, false, false)
	identityDir := fixture.paths.IdentityDir(inventoryIdentity)
	baselinePath := fixture.paths.RotationBaselinePath(inventoryIdentity)
	rootPath := crypto.KeyringPath(identityDir)
	snapshotPath := fixture.paths.RotationSnapshotPath(inventoryIdentity)
	baselineRenamed := false
	rootRenamed := false
	rootDirectorySynced := false
	cleanupDirectorySynced := false
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		switch {
		case op == fsutil.OpRename && path == baselinePath:
			baselineRenamed = true
		case op == fsutil.OpRename && path == rootPath:
			if !baselineRenamed {
				return errors.New("root published before completion baseline")
			}
			if _, err := os.Stat(snapshotPath); err != nil {
				return fmt.Errorf("snapshot absent at root publish: %w", err)
			}
			rootRenamed = true
		case op == fsutil.OpDirSync && path == identityDir && rootRenamed &&
			!rootDirectorySynced:
			if _, err := os.Stat(snapshotPath); err != nil {
				return fmt.Errorf("snapshot removed before root directory sync: %w", err)
			}
			rootDirectorySynced = true
		case op == fsutil.OpDirSync && path == identityDir &&
			rootDirectorySynced:
			if _, err := os.Stat(snapshotPath); !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("snapshot visible during cleanup directory sync: %v", err)
			}
			cleanupDirectorySynced = true
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })

	if _, err := CompleteRotation(
		fixture.paths,
		inventoryIdentity,
		fixture.kr,
		passphrase,
	); err != nil {
		t.Fatalf("CompleteRotation() error = %v", err)
	}
	if !baselineRenamed || !rootRenamed ||
		!rootDirectorySynced || !cleanupDirectorySynced {
		t.Fatalf(
			"completion ordering baseline=%v root=%v root-sync=%v cleanup-sync=%v",
			baselineRenamed,
			rootRenamed,
			rootDirectorySynced,
			cleanupDirectorySynced,
		)
	}
}

func TestCompleteRotationRejectsUnpinnedFinalPath(t *testing.T) {
	fixture, _, passphrase := startCompletionFixture(t, false, false, false)
	path := filepath.Join(
		fixture.paths.DeletedKeysDir(inventoryIdentity),
		"INJECTED.key",
	)
	if err := writeEnvelope(
		path,
		[]byte("injected"),
		crypto.AccountKeyContext("INJECTED"),
		fixture.kr,
	); err != nil {
		t.Fatalf("writeEnvelope(unpinned target) error = %v", err)
	}

	if _, err := CompleteRotation(
		fixture.paths,
		inventoryIdentity,
		fixture.kr,
		passphrase,
	); err == nil || !strings.Contains(err.Error(), "unpinned path") {
		t.Fatalf("CompleteRotation() error = %v, want final path-set rejection", err)
	}
	if _, pending := fixture.kr.PendingRotation(); !pending {
		t.Fatal("final path-set rejection closed the pending root")
	}
	if _, err := os.Stat(
		fixture.paths.RotationSnapshotPath(inventoryIdentity),
	); err != nil {
		t.Fatalf("final path-set rejection removed snapshot: %v", err)
	}
}

func TestCompleteRotationRetriesBaselineAfterDurabilityFailure(t *testing.T) {
	fixture, _, passphrase := startCompletionFixture(t, true, false, false)
	injected := errors.New("injected baseline directory sync failure")
	failed := false
	baselineRenamed := false
	baselinePath := fixture.paths.RotationBaselinePath(inventoryIdentity)
	baselineDir := filepath.Dir(
		baselinePath,
	)
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpRename && path == baselinePath {
			baselineRenamed = true
		}
		if op == fsutil.OpDirSync && path == baselineDir &&
			baselineRenamed && !failed {
			failed = true
			return injected
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })

	partial, err := CompleteRotation(
		fixture.paths,
		inventoryIdentity,
		fixture.kr,
		passphrase,
	)
	if !errors.Is(err, injected) {
		t.Fatalf("CompleteRotation() error = %v, want injected failure", err)
	}
	if partial == nil || partial.RootClosed {
		t.Fatalf("CompleteRotation() partial report = %#v", partial)
	}
	if _, pending := fixture.kr.PendingRotation(); !pending {
		t.Fatal("baseline durability failure closed the root")
	}
	fsutil.TestHook = nil

	retry, err := CompleteRotation(
		fixture.paths,
		inventoryIdentity,
		fixture.kr,
		passphrase,
	)
	if err != nil {
		t.Fatalf("CompleteRotation(retry) error = %v", err)
	}
	if !retry.BaselineAlreadyCurrent || retry.BaselineWritten ||
		!retry.RootClosed || !retry.SnapshotRemoved {
		t.Fatalf("CompleteRotation(retry) report = %#v", retry)
	}
}

func TestCompleteRotationSecondScanBlocksMutationAfterBaseline(t *testing.T) {
	fixture, _, passphrase := startCompletionFixture(t, true, false, false)
	policyPath := policy.PolicyPath(fixture.paths.Root(), inventoryIdentity)
	mutated := false
	baselineRenamed := false
	baselinePath := fixture.paths.RotationBaselinePath(inventoryIdentity)
	baselineDir := filepath.Dir(
		baselinePath,
	)
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpRename && path == baselinePath {
			baselineRenamed = true
		}
		if op == fsutil.OpDirSync && path == baselineDir &&
			baselineRenamed && !mutated {
			mutated = true
			data, err := os.ReadFile(policyPath)
			if err != nil {
				return err
			}
			data[0] ^= 1
			return os.WriteFile(policyPath, data, fsutil.StoreFilePerm)
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })

	if _, err := CompleteRotation(
		fixture.paths,
		inventoryIdentity,
		fixture.kr,
		passphrase,
	); err == nil {
		t.Fatal("CompleteRotation() accepted mutation after baseline publication")
	}
	if !mutated {
		t.Fatal("test did not inject the post-baseline mutation")
	}
	if _, pending := fixture.kr.PendingRotation(); !pending {
		t.Fatal("post-baseline mutation closed the root")
	}
}

func TestCompleteRotationRecoversVisibleCloseBeforeSnapshotCleanup(t *testing.T) {
	fixture, _, passphrase := startCompletionFixture(t, false, false, false)
	injected := errors.New("injected close directory sync failure")
	rootRenamed := false
	identityDir := fixture.paths.IdentityDir(inventoryIdentity)
	rootPath := crypto.KeyringPath(identityDir)
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpRename && path == rootPath {
			rootRenamed = true
		}
		if op == fsutil.OpDirSync && path == identityDir && rootRenamed {
			return injected
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })

	partial, err := CompleteRotation(
		fixture.paths,
		inventoryIdentity,
		fixture.kr,
		passphrase,
	)
	if !errors.Is(err, crypto.ErrRotationCommitDurabilityUnknown) ||
		!errors.Is(err, injected) {
		t.Fatalf("CompleteRotation() error = %v, want visible close failure", err)
	}
	if partial == nil || !partial.RootClosed || partial.SnapshotRemoved {
		t.Fatalf("CompleteRotation() partial report = %#v", partial)
	}
	if _, pending := fixture.kr.PendingRotation(); pending {
		t.Fatal("visible settled root was not adopted")
	}
	if _, err := os.Stat(
		fixture.paths.RotationSnapshotPath(inventoryIdentity),
	); err != nil {
		t.Fatalf("snapshot removed before close durability reconciliation: %v", err)
	}
	fsutil.TestHook = nil

	recovered, err := CompleteRotation(
		fixture.paths,
		inventoryIdentity,
		fixture.kr,
		passphrase,
	)
	if err != nil {
		t.Fatalf("CompleteRotation(recover close) error = %v", err)
	}
	if !recovered.RootClosed || !recovered.RecoveredClosedRoot ||
		!recovered.SnapshotRemoved {
		t.Fatalf("CompleteRotation(recover close) report = %#v", recovered)
	}
}

func TestCompleteRotationReportsSnapshotCleanupDurabilityFailure(t *testing.T) {
	fixture, _, passphrase := startCompletionFixture(t, false, false, false)
	injected := errors.New("injected snapshot cleanup directory sync failure")
	identityDir := fixture.paths.IdentityDir(inventoryIdentity)
	rootPath := crypto.KeyringPath(identityDir)
	rootRenamed := false
	rootSynced := false
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpRename && path == rootPath {
			rootRenamed = true
		}
		if op != fsutil.OpDirSync || path != identityDir || !rootRenamed {
			return nil
		}
		if !rootSynced {
			rootSynced = true
			return nil
		}
		return injected
	}
	t.Cleanup(func() { fsutil.TestHook = nil })

	partial, err := CompleteRotation(
		fixture.paths,
		inventoryIdentity,
		fixture.kr,
		passphrase,
	)
	if !errors.Is(err, injected) {
		t.Fatalf("CompleteRotation() error = %v, want cleanup failure", err)
	}
	if partial == nil || !partial.RootClosed || partial.SnapshotRemoved {
		t.Fatalf("CompleteRotation() partial report = %#v", partial)
	}
	if _, pending := fixture.kr.PendingRotation(); pending {
		t.Fatal("snapshot cleanup failure restored pending authority")
	}
	if _, err := os.Stat(
		fixture.paths.RotationSnapshotPath(inventoryIdentity),
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("snapshot removal is not visible after cleanup sync failure: %v", err)
	}
}

func startCompletionFixture(
	t *testing.T,
	rollbackEligible, diverged, priorBaseline bool,
) (inventoryFixture, *Snapshot, []byte) {
	t.Helper()
	fixture := newInventoryFixture(t)
	passphrase := []byte("rotation-completion-passphrase")
	prepareInventoryFixtureKeyringStore(t, fixture, passphrase)
	for _, path := range []string{
		fixture.paths.RotationSnapshotPath(inventoryIdentity),
		fixture.paths.RotationBaselinePath(inventoryIdentity),
	} {
		if err := fsutil.RemoveDurable(path); err != nil {
			t.Fatalf("RemoveDurable(%s) error = %v", path, err)
		}
	}

	if rollbackEligible {
		gen := fixture.paths.GenerationPaths(inventoryIdentity, inventoryGenB)
		manifest, err := genstore.ReadManifest(gen)
		if err != nil {
			t.Fatalf("ReadManifest() error = %v", err)
		}
		manifest.SourceRestoreID = "0123456789abcdef0123456789abcdef"
		encoded, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			t.Fatalf("MarshalIndent(manifest) error = %v", err)
		}
		if err := fsutil.WriteFileDurable(gen.ManifestPath(), encoded); err != nil {
			t.Fatalf("WriteFileDurable(manifest) error = %v", err)
		}
	}
	if diverged {
		path := filepath.Join(
			fixture.paths.GenerationPaths(
				inventoryIdentity,
				inventoryGenB,
			).KeysDir(),
			"ACCOUNT.key",
		)
		if err := writeEnvelope(
			path,
			bytes.Repeat([]byte("changed"), 2),
			crypto.AccountKeyContext("ACCOUNT"),
			fixture.kr,
		); err != nil {
			t.Fatalf("writeEnvelope(diverged current) error = %v", err)
		}
	}
	if priorBaseline {
		inventory, err := genstore.BuildInventory(
			fixture.paths.GenerationPaths(inventoryIdentity, inventoryGenB),
		)
		if err != nil {
			t.Fatalf("BuildInventory(prior baseline) error = %v", err)
		}
		baseline, err := NewBaseline(inventoryGenB, inventory)
		if err != nil {
			t.Fatalf("NewBaseline(prior) error = %v", err)
		}
		if err := WriteBaseline(
			fixture.paths,
			inventoryIdentity,
			baseline,
			fixture.kr,
		); err != nil {
			t.Fatalf("WriteBaseline(prior) error = %v", err)
		}
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
	return fixture, snapshot, passphrase
}
