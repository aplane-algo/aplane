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
	if err := ir.EnrollAuthorizedKey(key, "laptop"); err != nil {
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

	_, err := ir.RevokeAuthorizedKey(ssh.FingerprintSHA256(key))
	if err == nil || !strings.Contains(err.Error(), "injected dir sync failure") {
		t.Fatalf("RevokeAuthorizedKey() error = %v, want the publish failure", err)
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
	if err := ir.EnrollAuthorizedKey(existing, "one"); err != nil {
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
	if err := ir.EnrollAuthorizedKey(added, "two"); err == nil {
		t.Fatal("EnrollAuthorizedKey() succeeded despite the rename failure")
	}
	if ir.HasAuthorizedKey(added) || !ir.HasAuthorizedKey(existing) {
		t.Fatal("runtime registry changed after a failed publish")
	}
}
