// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package productruntime

import (
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// failSyncAndCorrupt makes the next directory sync fail and leaves the file
// at path unreadable, as a disk fault can: the runtime cannot read back
// what it tried to write.
func failSyncAndCorrupt(t *testing.T, path string) {
	t.Helper()
	fsutil.TestHook = func(op fsutil.HookOp, _ string) error {
		if op != fsutil.OpDirSync {
			return nil
		}
		fsutil.TestHook = nil
		if err := os.WriteFile(path, []byte("not a registry line\n"), 0o600); err != nil {
			t.Error(err)
		}
		return errors.New("injected dir sync failure")
	}
	t.Cleanup(func() { fsutil.TestHook = nil })
}

// A registry the runtime cannot read back after a failed write refuses every
// client, and is never written back from that empty view: a later change,
// even an unauthenticated client's enrollment request, waits for the file to
// be readable, and then keeps every key the file holds.
func TestUnreadableRegistryIsNeverWrittenBackEmpty(t *testing.T) {
	ir := New(Config{KeyPaths: storepaths.NewPaths(t.TempDir())})
	kept, other, newcomer := testSSHKey(t), testSSHKey(t), testSSHKey(t)
	if _, err := ir.EnrollAuthorizedKey(kept, "kept"); err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(ir.AuthorizedKeysPath())
	if err != nil {
		t.Fatal(err)
	}

	failSyncAndCorrupt(t, ir.AuthorizedKeysPath())
	if _, err := ir.EnrollAuthorizedKey(other, "other"); err == nil {
		t.Fatal("a write whose file could not be read back reported success")
	}
	if ir.HasAuthorizedKey(kept) {
		t.Fatal("an unreadable registry still grants a key")
	}

	if _, _, err := ir.QueueEnrollment(newcomer, "new", "10.0.0.9:1"); err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("QueueEnrollment() on an unreadable registry = %v, want a refusal naming it", err)
	}
	if data, _ := os.ReadFile(ir.AuthorizedKeysPath()); string(data) != "not a registry line\n" {
		t.Fatalf("the unreadable registry was overwritten: %q", data)
	}

	// The operator repairs the file. The next change reads it again and
	// keeps what it holds.
	if err := os.WriteFile(ir.AuthorizedKeysPath(), good, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ir.EnrollAuthorizedKey(other, "other"); err != nil {
		t.Fatalf("EnrollAuthorizedKey() after the repair = %v", err)
	}
	for name, key := range map[string]ssh.PublicKey{"kept": kept, "other": other} {
		if !ir.HasAuthorizedKey(key) {
			t.Fatalf("the %s key is not enrolled after the repair", name)
		}
	}
}

// The same for the enrollment queue: requests waiting in a queue file the
// runtime cannot read back are not dropped by the next request.
func TestUnreadableEnrollmentQueueIsNeverWrittenBackEmpty(t *testing.T) {
	ir := New(Config{KeyPaths: storepaths.NewPaths(t.TempDir())})
	waiting, second, third := testSSHKey(t), testSSHKey(t), testSSHKey(t)
	if _, _, err := ir.QueueEnrollment(waiting, "waiting", "10.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(ir.PendingEnrollmentsPath())
	if err != nil {
		t.Fatal(err)
	}

	failSyncAndCorrupt(t, ir.PendingEnrollmentsPath())
	if _, _, err := ir.QueueEnrollment(second, "second", "10.0.0.2:1"); err == nil {
		t.Fatal("a queue write whose file could not be read back reported success")
	}
	if _, _, err := ir.QueueEnrollment(third, "third", "10.0.0.3:1"); err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("QueueEnrollment() on an unreadable queue = %v, want a refusal naming it", err)
	}
	if data, _ := os.ReadFile(ir.PendingEnrollmentsPath()); string(data) != "not a registry line\n" {
		t.Fatalf("the unreadable queue was overwritten: %q", data)
	}

	if err := os.WriteFile(ir.PendingEnrollmentsPath(), good, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ir.QueueEnrollment(third, "third", "10.0.0.3:1"); err != nil {
		t.Fatalf("QueueEnrollment() after the repair = %v", err)
	}
	fingerprints := map[string]bool{}
	for _, entry := range ir.PendingEnrollments() {
		fingerprints[entry.Fingerprint] = true
	}
	for name, key := range map[string]ssh.PublicKey{"waiting": waiting, "third": third} {
		if !fingerprints[ssh.FingerprintSHA256(key)] {
			t.Fatalf("the %s request is not waiting after the repair (have %v)", name, fingerprints)
		}
	}
}
