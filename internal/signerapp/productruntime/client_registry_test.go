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

// A rejection whose queue write fails after the rename is reported, and the
// runtime adopts the queue on disk, which no longer holds the request.
func TestRejectEnrollmentFailedPublishResyncsQueue(t *testing.T) {
	ir := New(Config{KeyPaths: storepaths.NewPaths(t.TempDir())})
	key := testSSHKey(t)
	if pending, _, err := ir.QueueEnrollment(key, "laptop", "10.0.0.1:1"); err != nil || !pending {
		t.Fatalf("QueueEnrollment() = %v, %v", pending, err)
	}
	fsutil.TestHook = func(op fsutil.HookOp, _ string) error {
		if op == fsutil.OpDirSync {
			return errors.New("injected dir sync failure")
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()
	entry, rejected, err := ir.RejectEnrollment(ssh.FingerprintSHA256(key))
	if err == nil {
		t.Fatal("RejectEnrollment() succeeded despite the publish failure")
	}
	if !rejected || !errors.Is(err, ErrAppliedNotDurable) || entry.Label != "laptop" {
		t.Fatalf("RejectEnrollment() = (%+v, %v, %v), want the applied-not-durable outcome", entry, rejected, err)
	}
	if got := ir.PendingEnrollments(); len(got) != 0 {
		t.Fatalf("pending after failed rejection = %+v; the file no longer holds the request", got)
	}
}

// The queue follows the same rule as the registry: while syncs keep failing,
// a retried request or rejection reports the durability failure, and a
// retry succeeds only once a sync has.
func TestQueueRetriesRequireSuccessfulSync(t *testing.T) {
	ir := New(Config{KeyPaths: storepaths.NewPaths(t.TempDir())})
	key := testSSHKey(t)
	fingerprint := ssh.FingerprintSHA256(key)

	syncFails := true
	fsutil.TestHook = func(op fsutil.HookOp, _ string) error {
		if op == fsutil.OpDirSync && syncFails {
			return errors.New("injected dir sync failure")
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()

	// The first request is in the live queue: reported as pending and new,
	// so the caller records and announces it, with the durability failure.
	if pending, added, err := ir.QueueEnrollment(key, "laptop", "10.0.0.1:1"); !pending || !added || !errors.Is(err, ErrAppliedNotDurable) {
		t.Fatalf("first QueueEnrollment() = (%v, %v, %v), want pending and added with the applied-not-durable error", pending, added, err)
	}
	if got := ir.PendingEnrollments(); len(got) != 1 {
		t.Fatalf("pending = %+v; the file holds the request", got)
	}
	if pending, _, err := ir.QueueEnrollment(key, "laptop", "10.0.0.1:1"); err == nil || pending || errors.Is(err, ErrAppliedNotDurable) || !strings.Contains(err.Error(), "not durable") {
		t.Fatalf("retried QueueEnrollment() = (%v, %v), want the pending-durability failure with nothing applied", pending, err)
	}
	if _, rejected, err := ir.RejectEnrollment(fingerprint); err == nil || rejected || !strings.Contains(err.Error(), "not durable") {
		t.Fatalf("RejectEnrollment() during unsynced state = (%v, %v), want the pending-durability failure with nothing applied", rejected, err)
	}

	syncFails = false
	if _, rejected, err := ir.RejectEnrollment(fingerprint); err != nil || !rejected {
		t.Fatalf("RejectEnrollment() after syncs recover = (%v, %v)", rejected, err)
	}
	if got := ir.PendingEnrollments(); len(got) != 0 {
		t.Fatalf("pending after rejection = %+v, want none", got)
	}
}

// An approval whose registry write fails after the rename has enrolled the
// key: it is reported as enrolled with the durability failure, the request
// stays listed, and once syncs recover a repeat approval clears the request
// without reporting a second enrollment.
func TestApproveEnrollmentAppliedNotDurableReportsEnrollment(t *testing.T) {
	ir := New(Config{KeyPaths: storepaths.NewPaths(t.TempDir())})
	key := testSSHKey(t)
	fingerprint := ssh.FingerprintSHA256(key)
	if pending, _, err := ir.QueueEnrollment(key, "laptop", "10.0.0.1:1"); err != nil || !pending {
		t.Fatalf("QueueEnrollment() = %v, %v", pending, err)
	}

	syncFails := true
	fsutil.TestHook = func(op fsutil.HookOp, _ string) error {
		if op == fsutil.OpDirSync && syncFails {
			return errors.New("injected dir sync failure")
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()

	entry, enrolled, err := ir.ApproveEnrollment(fingerprint, "ops")
	if !enrolled || !errors.Is(err, ErrAppliedNotDurable) || entry.Label != "ops" || entry.RemoteAddr != "10.0.0.1:1" {
		t.Fatalf("ApproveEnrollment() = (%+v, %v, %v), want enrolled with the applied-not-durable error", entry, enrolled, err)
	}
	if !ir.HasAuthorizedKey(key) {
		t.Fatal("the registry file holds the key, so the runtime should honor it")
	}
	if got := ir.PendingEnrollments(); len(got) != 1 {
		t.Fatalf("pending after the incomplete approval = %+v, want the request still listed", got)
	}
	if _, enrolled, err := ir.ApproveEnrollment(fingerprint, "ops"); err == nil || enrolled || errors.Is(err, ErrAppliedNotDurable) {
		t.Fatalf("retry while syncs fail = (%v, %v), want the pending-durability failure with nothing applied", enrolled, err)
	}

	syncFails = false
	if _, enrolled, err := ir.ApproveEnrollment(fingerprint, "ops"); err != nil || enrolled {
		t.Fatalf("retry after syncs recover = (%v, %v), want success without a second enrollment", enrolled, err)
	}
	if got := ir.PendingEnrollments(); len(got) != 0 || !ir.HasAuthorizedKey(key) {
		t.Fatalf("after recovery: pending = %+v, authorized = %v", got, ir.HasAuthorizedKey(key))
	}
}
