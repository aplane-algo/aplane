// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotationinventory

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/fsutil"
)

func TestResumeRotationRewrapsOnlyPinnedMutableConsumers(t *testing.T) {
	fixture, snapshot := startResumeFixture(t)
	historicalPrefix := "identities/default/generations/" + inventoryGenA + "/"
	before := make(map[string][]byte, len(snapshot.Inventory))
	for _, entry := range snapshot.Inventory {
		before[entry.Path] = readInventoryEntry(t, fixture, entry)
	}

	report, err := ResumeRotation(fixture.paths, inventoryIdentity, fixture.kr)
	if err != nil {
		t.Fatalf("ResumeRotation() error = %v", err)
	}
	if report.SnapshotEntries != len(snapshot.Inventory) {
		t.Fatalf(
			"SnapshotEntries = %d, want %d",
			report.SnapshotEntries,
			len(snapshot.Inventory),
		)
	}
	if report.Rewrapped == 0 || report.Resigned != 2 {
		t.Fatalf("ResumeRotation() report = %#v", report)
	}
	if _, pending := fixture.kr.PendingRotation(); !pending {
		t.Fatal("ResumeRotation() prematurely closed the pending root")
	}
	if _, err := os.Stat(
		fixture.paths.RotationSnapshotPath(),
	); err != nil {
		t.Fatalf("rotation snapshot removed before completion: %v", err)
	}

	for _, entry := range snapshot.Inventory {
		data := readInventoryEntry(t, fixture, entry)
		switch {
		case strings.HasPrefix(entry.Path, historicalPrefix):
			if !bytes.Equal(data, before[entry.Path]) {
				t.Errorf("historical entry %q was rewritten", entry.Path)
			}
		case entry.ObjectClass != "":
			term, err := crypto.EnvelopeTerm(data)
			if err != nil {
				t.Errorf("EnvelopeTerm(%q) error = %v", entry.Path, err)
			} else if term != snapshot.ToTerm {
				t.Errorf(
					"mutable envelope %q term = %d, want %d",
					entry.Path,
					term,
					snapshot.ToTerm,
				)
			}
		case entry.Kind == KindPolicySidecar ||
			entry.Kind == KindNodeRoleSidecar:
			if bytes.Equal(data, before[entry.Path]) {
				t.Errorf("integrity sidecar %q was not re-signed", entry.Path)
			}
		default:
			if !bytes.Equal(data, before[entry.Path]) {
				t.Errorf("plaintext entry %q changed", entry.Path)
			}
		}
	}
	if _, err := Scan(fixture.paths, inventoryIdentity, fixture.kr); err != nil {
		t.Fatalf("Scan(resumed store) error = %v", err)
	}

	retry, err := ResumeRotation(fixture.paths, inventoryIdentity, fixture.kr)
	if err != nil {
		t.Fatalf("ResumeRotation(retry) error = %v", err)
	}
	if retry.Rewrapped != 0 || retry.Resigned != 0 ||
		retry.AlreadyTarget != report.Rewrapped+report.Resigned {
		t.Fatalf("ResumeRotation(retry) report = %#v, first = %#v", retry, report)
	}
}

func TestResumeRotationReconcilesCrashOrphanedDurableTemp(t *testing.T) {
	fixture, snapshot := startResumeFixture(t)
	index := slices.IndexFunc(snapshot.Inventory, func(entry Entry) bool {
		return entry.Kind == KindAccountKey &&
			!strings.Contains(entry.Path, "/generations/"+inventoryGenA+"/")
	})
	if index < 0 {
		t.Fatal("fixture snapshot has no mutable account key")
	}
	target := filepath.Join(
		fixture.paths.Root(),
		filepath.FromSlash(snapshot.Inventory[index].Path),
	)
	residue := target + ".tmp-crash"
	if err := os.WriteFile(residue, []byte("orphaned durable temp"), 0o600); err != nil {
		t.Fatalf("WriteFile(residue) error = %v", err)
	}

	if _, err := ResumeRotation(fixture.paths, inventoryIdentity, fixture.kr); err != nil {
		t.Fatalf("ResumeRotation() error = %v", err)
	}
	if _, err := os.Stat(residue); !os.IsNotExist(err) {
		t.Fatalf("durable temp residue survived resume: %v", err)
	}
	if _, err := Scan(fixture.paths, inventoryIdentity, fixture.kr); err != nil {
		t.Fatalf("Scan() after residue reconciliation error = %v", err)
	}
}

func TestResumeRotationRejectsRetiringTermInputThatDiffersFromSnapshot(t *testing.T) {
	fixture, snapshot := startResumeFixture(t)
	entry := snapshotEntry(
		t,
		snapshot,
		"identities/default/generations/"+inventoryGenB+"/keys/ACCOUNT.key",
	)
	retiring := cryptotest.Keyring(
		t,
		bytes.Repeat([]byte{0x71}, 32),
	)
	forged, err := retiring.Seal(
		[]byte("attacker-controlled replacement"),
		crypto.ObjectContext{
			Class:    entry.ObjectClass,
			Selector: entry.ObjectSelector,
		},
	)
	if err != nil {
		t.Fatalf("Seal(forged retiring-term input) error = %v", err)
	}
	path := filepath.Join(
		fixture.paths.Root(),
		filepath.FromSlash(entry.Path),
	)
	if err := fsutil.WriteFileDurable(path, forged); err != nil {
		t.Fatalf("WriteFileDurable(forged input) error = %v", err)
	}

	if _, err := ResumeRotation(
		fixture.paths,
		inventoryIdentity,
		fixture.kr,
	); err == nil || !strings.Contains(err.Error(), "does not match snapshot") {
		t.Fatalf("ResumeRotation() error = %v, want exact snapshot rejection", err)
	}
	remaining, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(forged input) error = %v", err)
	}
	term, err := crypto.EnvelopeTerm(remaining)
	if err != nil {
		t.Fatalf("EnvelopeTerm(forged input) error = %v", err)
	}
	if term != snapshot.FromTerm {
		t.Fatalf("forged input was laundered to term %d", term)
	}
}

func TestResumeRotationRetriesVisibleTargetAfterDirSyncFailure(t *testing.T) {
	fixture, _ := startResumeFixture(t)
	injected := errors.New("injected directory sync failure")
	failed := false
	fsutil.TestHook = func(op fsutil.HookOp, _ string) error {
		if op == fsutil.OpDirSync && !failed {
			failed = true
			return injected
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })

	partial, err := ResumeRotation(fixture.paths, inventoryIdentity, fixture.kr)
	if !errors.Is(err, injected) {
		t.Fatalf("ResumeRotation() error = %v, want injected failure", err)
	}
	if !failed || partial == nil {
		t.Fatalf("ResumeRotation() partial report = %#v, failed = %v", partial, failed)
	}
	fsutil.TestHook = nil

	retry, err := ResumeRotation(fixture.paths, inventoryIdentity, fixture.kr)
	if err != nil {
		t.Fatalf("ResumeRotation(retry) error = %v", err)
	}
	if retry.AlreadyTarget == 0 {
		t.Fatalf("ResumeRotation(retry) did not accept visible target: %#v", retry)
	}
	if _, err := Scan(fixture.paths, inventoryIdentity, fixture.kr); err != nil {
		t.Fatalf("Scan(retried store) error = %v", err)
	}
}

func TestResumeRotationRejectsChangedPinnedPlaintext(t *testing.T) {
	fixture, snapshot := startResumeFixture(t)
	entry := snapshotEntry(
		t,
		snapshot,
		"identities/default/policy.yaml",
	)
	path := filepath.Join(
		fixture.paths.Root(),
		filepath.FromSlash(entry.Path),
	)
	changed := readInventoryEntry(t, fixture, entry)
	changed = bytes.Clone(changed)
	changed[0] ^= 1
	if err := fsutil.WriteFileDurable(path, changed); err != nil {
		t.Fatalf("WriteFileDurable(changed policy) error = %v", err)
	}

	if _, err := ResumeRotation(
		fixture.paths,
		inventoryIdentity,
		fixture.kr,
	); err == nil || !strings.Contains(err.Error(), "does not match snapshot SHA-256") {
		t.Fatalf("ResumeRotation() error = %v, want pinned digest rejection", err)
	}
}

func TestResumeRotationRejectsSymlinkedPinnedInput(t *testing.T) {
	fixture, snapshot := startResumeFixture(t)
	entry := snapshotEntry(
		t,
		snapshot,
		"identities/default/generations/"+inventoryGenB+"/keys/ACCOUNT.key",
	)
	path := filepath.Join(
		fixture.paths.Root(),
		filepath.FromSlash(entry.Path),
	)
	outside := filepath.Join(t.TempDir(), "outside.key")
	outsideBytes := []byte("must remain untouched")
	if err := os.WriteFile(outside, outsideBytes, fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(outside) error = %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove(pinned input) error = %v", err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatalf("Symlink(pinned input) error = %v", err)
	}

	if _, err := ResumeRotation(
		fixture.paths,
		inventoryIdentity,
		fixture.kr,
	); err == nil {
		t.Fatal("ResumeRotation() accepted symlinked pinned input")
	}
	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatalf("ReadFile(outside) error = %v", err)
	}
	if !bytes.Equal(got, outsideBytes) {
		t.Fatalf("outside target changed to %q", got)
	}
}

func TestResumeRotationRequiresPendingRoot(t *testing.T) {
	fixture := newInventoryFixture(t)
	if report, err := ResumeRotation(
		fixture.paths,
		inventoryIdentity,
		fixture.kr,
	); !errors.Is(err, ErrNoRotationPending) || report != nil {
		t.Fatalf("ResumeRotation() = (%#v, %v), want ErrNoRotationPending", report, err)
	}
}

func startResumeFixture(t *testing.T) (inventoryFixture, *Snapshot) {
	t.Helper()
	fixture := newInventoryFixture(t)
	passphrase := []byte("rotation-resume-passphrase")
	prepareInventoryFixtureKeyringStore(t, fixture, passphrase)
	for _, path := range []string{
		fixture.paths.RotationSnapshotPath(),
		fixture.paths.RotationBaselinePath(),
	} {
		if err := fsutil.RemoveDurable(path); err != nil {
			t.Fatalf("RemoveDurable(%s) error = %v", path, err)
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
	return fixture, snapshot
}

func snapshotEntry(t *testing.T, snapshot *Snapshot, path string) Entry {
	t.Helper()
	for _, entry := range snapshot.Inventory {
		if entry.Path == path {
			return entry
		}
	}
	t.Fatalf("snapshot entry %q not found", path)
	return Entry{}
}

func readInventoryEntry(
	t *testing.T,
	fixture inventoryFixture,
	entry Entry,
) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(
		fixture.paths.Root(),
		filepath.FromSlash(entry.Path),
	))
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", entry.Path, err)
	}
	return data
}
