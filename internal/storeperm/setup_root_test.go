// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeperm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareManagedRootClosesExistingRoot(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "signer")
	if err := os.Mkdir(root, 0o770); err != nil {
		t.Fatal(err)
	}

	result, err := PrepareManagedRoot(root, os.Geteuid(), os.Getegid())
	if err != nil {
		t.Fatal(err)
	}
	if result.Created {
		t.Fatal("PrepareManagedRoot() reported existing root as created")
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("root mode = %04o, want 0700", got)
	}
}

func TestPrepareManagedRootCreatesMissingComponentsUnderTrustedParent(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "new", "signer")

	result, err := PrepareManagedRoot(root, os.Geteuid(), os.Getegid())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Created {
		t.Fatal("PrepareManagedRoot() did not report final root creation")
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("root mode = %04o, want 0700", got)
	}
}

func TestPrepareManagedRootRejectsWritableAncestorBeforeMutation(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	writable := filepath.Join(parent, "operator-controlled")
	if err := os.Mkdir(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(writable, "signer")

	_, err := PrepareManagedRoot(root, os.Geteuid(), os.Getegid())
	if err == nil || !strings.Contains(err.Error(), "group/other writable") {
		t.Fatalf("PrepareManagedRoot() error = %v, want writable-ancestor rejection", err)
	}
	if _, statErr := os.Lstat(root); !os.IsNotExist(statErr) {
		t.Fatalf("rejected preparation created store root: %v", statErr)
	}
}

func TestPrepareManagedRootRejectsSymlinkWithoutTouchingReferent(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	referent := filepath.Join(parent, "referent")
	if err := os.Mkdir(referent, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "signer")
	if err := os.Symlink(referent, link); err != nil {
		t.Fatal(err)
	}

	if _, err := PrepareManagedRoot(link, os.Geteuid(), os.Getegid()); err == nil {
		t.Fatal("PrepareManagedRoot(symlink) error = nil")
	}
	info, err := os.Stat(referent)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("referent mode = %04o, want 0755", got)
	}
}

func TestPrepareManagedRootRejectsReplacedFinalEntry(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "signer")
	detached := filepath.Join(parent, "detached")
	if err := os.Mkdir(root, 0o770); err != nil {
		t.Fatal(err)
	}

	_, err := prepareManagedRoot(root, os.Geteuid(), os.Getegid(), func() {
		if renameErr := os.Rename(root, detached); renameErr != nil {
			t.Fatalf("replace hook Rename() error = %v", renameErr)
		}
		if mkdirErr := os.Mkdir(root, 0o755); mkdirErr != nil {
			t.Fatalf("replace hook Mkdir() error = %v", mkdirErr)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "changed during managed setup") {
		t.Fatalf("prepareManagedRoot(replaced leaf) error = %v, want binding rejection", err)
	}
	replacement, statErr := os.Stat(root)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if got := replacement.Mode().Perm(); got != 0o755 {
		t.Fatalf("replacement mode = %04o, want 0755 untouched", got)
	}
}
