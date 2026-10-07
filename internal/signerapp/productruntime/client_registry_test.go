// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package productruntime

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func testSSHKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// A revocation whose registry write fails after the rename is reported as a
// failure, and the runtime adopts the registry on disk rather than keep
// granting the revoked key: the file no longer holds it.
func TestRevokeAuthorizedKeyFailedPublishDoesNotRetainStaleAuthority(t *testing.T) {
	ir := New(Config{KeyPaths: storepaths.NewPaths(t.TempDir())})
	key := testSSHKey(t)
	if _, err := ir.EnrollAuthorizedKey(key, "laptop"); err != nil {
		t.Fatalf("EnrollAuthorizedKey() error = %v", err)
	}
	if err := ir.LoadAuthorizedKeys(); err != nil {
		t.Fatalf("LoadAuthorizedKeys() error = %v", err)
	}

	fsutil.TestHook = func(op fsutil.HookOp, _ string) error {
		if op == fsutil.OpDirSync {
			return errors.New("injected dir sync failure")
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()

	entry, revoked, err := ir.RevokeAuthorizedKey(ssh.FingerprintSHA256(key))
	if err == nil || !strings.Contains(err.Error(), "injected dir sync failure") {
		t.Fatalf("RevokeAuthorizedKey() error = %v, want the publish failure", err)
	}
	if !revoked || !errors.Is(err, ErrAppliedNotDurable) || entry.Label != "laptop" {
		t.Fatalf("RevokeAuthorizedKey() = (%+v, %v, %v), want the applied-not-durable outcome", entry, revoked, err)
	}
	if ir.HasAuthorizedKey(key) {
		t.Fatal("revoked key still authorized in memory after the file dropped it")
	}
	fsutil.TestHook = nil
	if err := ir.LoadAuthorizedKeys(); err != nil || ir.HasAuthorizedKey(key) {
		t.Fatalf("after reload: err = %v, authorized = %v", err, ir.HasAuthorizedKey(key))
	}
}

// A publish that fails before the rename leaves both the file and the
// runtime's view unchanged.
func TestEnrollAuthorizedKeyFailedStagingKeepsRegistry(t *testing.T) {
	ir := New(Config{KeyPaths: storepaths.NewPaths(t.TempDir())})
	existing := testSSHKey(t)
	if _, err := ir.EnrollAuthorizedKey(existing, "one"); err != nil {
		t.Fatal(err)
	}
	fsutil.TestHook = func(op fsutil.HookOp, _ string) error {
		if op == fsutil.OpRename {
			return errors.New("injected rename failure")
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()

	added := testSSHKey(t)
	if enrolled, err := ir.EnrollAuthorizedKey(added, "two"); err == nil || enrolled || errors.Is(err, ErrAppliedNotDurable) {
		t.Fatalf("EnrollAuthorizedKey() = (%v, %v), want a plain failure with nothing applied", enrolled, err)
	}
	if ir.HasAuthorizedKey(added) || !ir.HasAuthorizedKey(existing) {
		t.Fatal("runtime registry changed after a failed publish")
	}
}

// While directory syncs keep failing, retrying an enrollment keeps failing
// too, even though the file already holds the key: success is acknowledged
// only once a sync has made the registry durable. A revocation retried in
// the same state reports the durability failure, not "not enrolled".
func TestRegistryRetriesRequireSuccessfulSync(t *testing.T) {
	ir := New(Config{KeyPaths: storepaths.NewPaths(t.TempDir())})
	key := testSSHKey(t)

	syncFails := true
	var dirSyncs int
	fsutil.TestHook = func(op fsutil.HookOp, _ string) error {
		if op != fsutil.OpDirSync {
			return nil
		}
		dirSyncs++
		if syncFails {
			return errors.New("injected dir sync failure")
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()

	// The first attempt installs the key: it is reported as enrolled, so the
	// caller audits it, together with the durability failure.
	if enrolled, err := ir.EnrollAuthorizedKey(key, "laptop"); !enrolled || !errors.Is(err, ErrAppliedNotDurable) {
		t.Fatalf("first EnrollAuthorizedKey() = (%v, %v), want enrolled with the applied-not-durable error", enrolled, err)
	}
	if !ir.HasAuthorizedKey(key) {
		t.Fatal("the file holds the key, so the runtime should honor it")
	}
	// A retry re-publishes the unsynced file and fails before applying
	// anything, so it is not reported as a fresh enrollment.
	if enrolled, err := ir.EnrollAuthorizedKey(key, "laptop"); err == nil || enrolled || errors.Is(err, ErrAppliedNotDurable) || !strings.Contains(err.Error(), "not durable") {
		t.Fatalf("retry = (%v, %v), want the pending-durability failure with nothing applied", enrolled, err)
	}
	if _, revoked, err := ir.RevokeAuthorizedKey(ssh.FingerprintSHA256(key)); err == nil || revoked || !strings.Contains(err.Error(), "not durable") {
		t.Fatalf("revoke during unsynced state = (%v, %v), want the pending-durability failure with nothing applied", revoked, err)
	}
	if !ir.HasAuthorizedKey(key) {
		t.Fatal("a refused revocation must not drop the key")
	}

	syncFails = false
	before := dirSyncs
	if enrolled, err := ir.EnrollAuthorizedKey(key, "laptop"); err != nil || enrolled {
		t.Fatalf("retry after syncs recover = (%v, %v), want success without a fresh enrollment", enrolled, err)
	}
	if dirSyncs != before+1 {
		t.Fatalf("directory syncs during the successful retry = %d, want exactly 1", dirSyncs-before)
	}
	if _, err := ir.EnrollAuthorizedKey(key, "laptop"); err != nil || dirSyncs != before+1 {
		t.Fatalf("once durable, an unchanged enrollment must write nothing: err = %v, syncs = %d", err, dirSyncs-before)
	}
	if _, _, err := ir.RevokeAuthorizedKey(ssh.FingerprintSHA256(key)); err != nil || ir.HasAuthorizedKey(key) {
		t.Fatalf("revoke after recovery: err = %v, authorized = %v", err, ir.HasAuthorizedKey(key))
	}
}
