// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/fsutil"
)

func TestStartRotationCommitsPendingAuthorityAndR5Guard(t *testing.T) {
	dir := t.TempDir()
	passphrase := []byte("rotation-passphrase")
	kr, err := CreateKeyringStore(dir, passphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	t.Cleanup(kr.Zero)

	oldEnvelope, err := kr.Seal([]byte("old authority"), AccountKeyContext("ACCOUNT"))
	if err != nil {
		t.Fatalf("Seal(old) error = %v", err)
	}
	oldTerm, oldMAC, err := kr.SignIntegrity(IntegrityDomainPolicy, []byte("policy"))
	if err != nil {
		t.Fatalf("SignIntegrity(old) error = %v", err)
	}
	anchor, err := NewHistoricalGenerationAnchor(
		"gen-1785300000-cafef00d",
		[]byte("exact historical seal"),
	)
	if err != nil {
		t.Fatalf("NewHistoricalGenerationAnchor() error = %v", err)
	}
	snapshotPath := filepath.Join(dir, "rotation.snapshot.enc")
	var snapshotBytes []byte
	writerCalls := 0
	writer := func(
		target *Keyring,
		fromTerm, toTerm int64,
	) (RotationSnapshotReference, error) {
		writerCalls++
		if fromTerm != 1 || toTerm != 2 || target.CurrentTerm() != 2 {
			t.Fatalf(
				"snapshot writer terms = %d -> %d, target %d",
				fromTerm,
				toTerm,
				target.CurrentTerm(),
			)
		}
		sealed, err := target.Seal([]byte("cutover"), RotationSnapshotContext())
		if err != nil {
			return RotationSnapshotReference{}, err
		}
		if err := fsutil.WriteFileDurable(snapshotPath, sealed); err != nil {
			return RotationSnapshotReference{}, err
		}
		snapshotBytes = slices.Clone(sealed)
		return NewRotationSnapshotReference(sealed)
	}

	if err := StartRotation(
		dir,
		kr,
		passphrase,
		[]HistoricalGenerationAnchor{anchor},
		writer,
	); err != nil {
		t.Fatalf("StartRotation() error = %v", err)
	}
	if writerCalls != 1 {
		t.Fatalf("snapshot writer calls = %d, want 1", writerCalls)
	}
	state, pending := kr.PendingRotation()
	if !pending || state.FromTerm != 1 || state.ToTerm != 2 {
		t.Fatalf("PendingRotation() = (%#v, %v)", state, pending)
	}
	if err := state.Snapshot.VerifyExact(snapshotBytes); err != nil {
		t.Fatalf("pending snapshot reference error = %v", err)
	}
	if anchors := kr.HistoricalGenerationAnchors(); !slices.Equal(
		anchors,
		[]HistoricalGenerationAnchor{anchor},
	) {
		t.Fatalf("historical anchors = %#v", anchors)
	}
	if plaintext, err := kr.Open(oldEnvelope, AccountKeyContext("ACCOUNT")); err != nil {
		t.Fatalf("Open(retiring term) error = %v", err)
	} else {
		ZeroBytes(plaintext)
	}
	if err := kr.VerifyIntegrity(
		IntegrityDomainPolicy,
		[]byte("policy"),
		oldTerm,
		oldMAC,
	); err != nil {
		t.Fatalf("VerifyIntegrity(retiring term) error = %v", err)
	}
	newEnvelope, err := kr.Seal([]byte("new authority"), AccountKeyContext("ACCOUNT"))
	if err != nil {
		t.Fatalf("Seal(new) error = %v", err)
	}
	if term, err := EnvelopeTerm(newEnvelope); err != nil || term != 2 {
		t.Fatalf("new envelope term = %d, %v, want 2", term, err)
	}

	reopened, err := OpenKeyringStore(dir, passphrase)
	if err != nil {
		t.Fatalf("OpenKeyringStore() error = %v", err)
	}
	defer reopened.Zero()
	reopenedState, reopenedPending := reopened.PendingRotation()
	if !reopenedPending || reopenedState != state {
		t.Fatalf("reopened pending state = (%#v, %v), want %#v", reopenedState, reopenedPending, state)
	}
	if plaintext, err := reopened.Open(oldEnvelope, AccountKeyContext("ACCOUNT")); err != nil {
		t.Fatalf("reopened Open(retiring term) error = %v", err)
	} else {
		ZeroBytes(plaintext)
	}

	secondWriterCalled := false
	err = StartRotation(
		dir,
		kr,
		passphrase,
		[]HistoricalGenerationAnchor{anchor},
		func(*Keyring, int64, int64) (RotationSnapshotReference, error) {
			secondWriterCalled = true
			return RotationSnapshotReference{}, nil
		},
	)
	if !errors.Is(err, ErrRotationAlreadyPending) {
		t.Fatalf("StartRotation(second) error = %v, want R5 guard", err)
	}
	if secondWriterCalled {
		t.Fatal("R5 guard ran the second snapshot writer")
	}
	if kr.CurrentTerm() != 2 {
		t.Fatalf("current term after rejected second append = %d, want 2", kr.CurrentTerm())
	}
	if err := kr.RequireSettled(); !errors.Is(err, ErrRotationPending) {
		t.Fatalf("RequireSettled() error = %v, want pending sentinel", err)
	}
}

func TestStartRotationFailureBeforeRootRenameLeavesOldAuthority(t *testing.T) {
	dir := t.TempDir()
	passphrase := []byte("rotation-rename-failure")
	kr, err := CreateKeyringStore(dir, passphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	t.Cleanup(kr.Zero)
	injected := errors.New("injected root rename failure")
	snapshotPath := filepath.Join(dir, "rotation.snapshot.enc")
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpRename && path == KeyringPath(dir) {
			return injected
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })

	err = StartRotation(
		dir,
		kr,
		passphrase,
		[]HistoricalGenerationAnchor{},
		func(target *Keyring, _, _ int64) (RotationSnapshotReference, error) {
			sealed, err := target.Seal([]byte("cutover"), RotationSnapshotContext())
			if err != nil {
				return RotationSnapshotReference{}, err
			}
			if err := fsutil.WriteFileDurable(snapshotPath, sealed); err != nil {
				return RotationSnapshotReference{}, err
			}
			return NewRotationSnapshotReference(sealed)
		},
	)
	if !errors.Is(err, injected) {
		t.Fatalf("StartRotation() error = %v, want injected rename failure", err)
	}
	if kr.CurrentTerm() != 1 {
		t.Fatalf("current term after pre-publish failure = %d, want 1", kr.CurrentTerm())
	}
	if _, pending := kr.PendingRotation(); pending {
		t.Fatal("pre-publish failure left in-memory rotation pending")
	}
	if _, err := os.Stat(snapshotPath); err != nil {
		t.Fatalf("durable pre-root snapshot orphan is missing: %v", err)
	}
	reopened, err := OpenKeyringStore(dir, passphrase)
	if err != nil {
		t.Fatalf("OpenKeyringStore() error = %v", err)
	}
	defer reopened.Zero()
	if reopened.CurrentTerm() != 1 {
		t.Fatalf("on-disk term after pre-publish failure = %d, want 1", reopened.CurrentTerm())
	}
}

func TestStartRotationAdoptsVisibleRootOnDirectorySyncFailure(t *testing.T) {
	dir := t.TempDir()
	passphrase := []byte("rotation-dir-sync-failure")
	kr, err := CreateKeyringStore(dir, passphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	t.Cleanup(kr.Zero)
	injected := errors.New("injected root directory sync failure")
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && path == dir {
			return injected
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })

	err = StartRotation(
		dir,
		kr,
		passphrase,
		[]HistoricalGenerationAnchor{},
		func(target *Keyring, _, _ int64) (RotationSnapshotReference, error) {
			sealed, err := target.Seal([]byte("cutover"), RotationSnapshotContext())
			if err != nil {
				return RotationSnapshotReference{}, err
			}
			// The crypto unit test isolates the root's post-rename failure;
			// rotationinventory tests the snapshot's durable ordering.
			return NewRotationSnapshotReference(sealed)
		},
	)
	if !errors.Is(err, ErrRotationCommitDurabilityUnknown) ||
		!errors.Is(err, injected) {
		t.Fatalf("StartRotation() error = %v, want visible durability-unknown root", err)
	}
	if kr.CurrentTerm() != 2 {
		t.Fatalf("in-memory current term = %d, want visible term 2", kr.CurrentTerm())
	}
	if _, pending := kr.PendingRotation(); !pending {
		t.Fatal("visible durability-unknown root did not install the R5 guard")
	}
	reopened, err := OpenKeyringStore(dir, passphrase)
	if err != nil {
		t.Fatalf("OpenKeyringStore(visible root) error = %v", err)
	}
	defer reopened.Zero()
	if reopened.CurrentTerm() != 2 {
		t.Fatalf("visible on-disk current term = %d, want 2", reopened.CurrentTerm())
	}
}

func TestStartRotationPreservesExistingHistoricalAnchors(t *testing.T) {
	dir := t.TempDir()
	passphrase := []byte("rotation-anchor-preservation")
	kr, err := CreateKeyringStore(dir, passphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	t.Cleanup(kr.Zero)
	anchor, err := NewHistoricalGenerationAnchor(
		"gen-1785300000-cafef00d",
		[]byte("historical seal"),
	)
	if err != nil {
		t.Fatalf("NewHistoricalGenerationAnchor() error = %v", err)
	}
	kr.historicalAnchors = []HistoricalGenerationAnchor{anchor}
	if err := WriteKeyring(dir, kr, passphrase); err != nil {
		t.Fatalf("WriteKeyring(anchor) error = %v", err)
	}
	writerCalled := false
	err = StartRotation(
		dir,
		kr,
		passphrase,
		[]HistoricalGenerationAnchor{},
		func(*Keyring, int64, int64) (RotationSnapshotReference, error) {
			writerCalled = true
			return RotationSnapshotReference{}, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "would be dropped or changed") {
		t.Fatalf("StartRotation(drop anchor) error = %v", err)
	}
	if writerCalled {
		t.Fatal("invalid anchor replacement reached snapshot publication")
	}
	if kr.CurrentTerm() != 1 {
		t.Fatalf("current term after anchor rejection = %d, want 1", kr.CurrentTerm())
	}
}

func TestPendingAuthoritySetExcludesOlderResidentTerms(t *testing.T) {
	key1 := bytes.Repeat([]byte{0xd1}, argon2KeyLen)
	key2 := bytes.Repeat([]byte{0xd2}, argon2KeyLen)
	key3 := bytes.Repeat([]byte{0xd3}, argon2KeyLen)
	term1, err := NewKeyringFromTermKey(1, key1)
	if err != nil {
		t.Fatalf("NewKeyringFromTermKey(1) error = %v", err)
	}
	defer term1.Zero()
	term2, err := NewKeyringFromTermKey(2, key2)
	if err != nil {
		t.Fatalf("NewKeyringFromTermKey(2) error = %v", err)
	}
	defer term2.Zero()
	pending, err := NewKeyringFromTermKeys(
		3,
		map[int64][]byte{1: key1, 2: key2, 3: key3},
	)
	if err != nil {
		t.Fatalf("NewKeyringFromTermKeys() error = %v", err)
	}
	defer pending.Zero()
	pending.rotation = &rotationDescriptor{
		FromTerm:       2,
		SnapshotSHA256: strings.Repeat("a", sha256HexLength),
		SnapshotSize:   100,
	}

	envelope1, err := term1.Seal([]byte("term one"), AccountKeyContext("ACCOUNT"))
	if err != nil {
		t.Fatalf("Seal(term 1) error = %v", err)
	}
	envelope2, err := term2.Seal([]byte("term two"), AccountKeyContext("ACCOUNT"))
	if err != nil {
		t.Fatalf("Seal(term 2) error = %v", err)
	}
	envelope3, err := pending.Seal([]byte("term three"), AccountKeyContext("ACCOUNT"))
	if err != nil {
		t.Fatalf("Seal(term 3) error = %v", err)
	}
	if _, err := pending.Open(envelope1, AccountKeyContext("ACCOUNT")); err == nil ||
		!strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("Open(older resident term) error = %v, want authority rejection", err)
	}
	for term, envelope := range map[int64][]byte{2: envelope2, 3: envelope3} {
		plaintext, err := pending.Open(envelope, AccountKeyContext("ACCOUNT"))
		if err != nil {
			t.Fatalf("Open(authority term %d) error = %v", term, err)
		}
		ZeroBytes(plaintext)
	}
}

func TestHistoricalGenerationAnchorsReturnsDefensiveCopy(t *testing.T) {
	kr, err := NewKeyring()
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	defer kr.Zero()
	anchor, err := NewHistoricalGenerationAnchor(
		"gen-1785300000-cafef00d",
		[]byte("historical seal"),
	)
	if err != nil {
		t.Fatalf("NewHistoricalGenerationAnchor() error = %v", err)
	}
	kr.historicalAnchors = []HistoricalGenerationAnchor{anchor}
	got := kr.HistoricalGenerationAnchors()
	got[0].SealSHA256 = strings.Repeat("0", 64)
	if kr.historicalAnchors[0] != anchor {
		t.Fatal("HistoricalGenerationAnchors() exposed mutable root state")
	}
	if found, ok := kr.HistoricalGenerationAnchor(anchor.GenerationID); !ok || found != anchor {
		t.Fatalf("HistoricalGenerationAnchor() = (%#v, %v)", found, ok)
	}
	if _, ok := kr.HistoricalGenerationAnchor("gen-1785300001-deadbeef"); ok {
		t.Fatal("HistoricalGenerationAnchor() found an absent generation")
	}
	if bytes.Equal([]byte(got[0].SealSHA256), []byte(anchor.SealSHA256)) {
		t.Fatal("test mutation did not change the returned copy")
	}
}
