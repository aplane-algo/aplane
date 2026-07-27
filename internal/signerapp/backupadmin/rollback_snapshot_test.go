// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/keys"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestCaptureAndRestoreActivationSnapshot(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	if err := os.MkdirAll(paths.KeysDir(identityID), 0o750); err != nil {
		t.Fatalf("MkdirAll(keys) error = %v", err)
	}
	priorPath := filepath.Join(paths.KeysDir(identityID), "prior.key")
	if err := os.WriteFile(priorPath, []byte("prior"), 0o600); err != nil {
		t.Fatalf("WriteFile(prior) error = %v", err)
	}

	snapshot, err := captureActivationSnapshot(paths, identityID, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("captureActivationSnapshot() error = %v", err)
	}
	defer snapshot.Zero()
	if !snapshot.Directories[0].Existed || snapshot.Directories[1].Existed {
		t.Fatalf("snapshot directories = %+v", snapshot.Directories)
	}

	if err := os.WriteFile(priorPath, []byte("changed"), 0o600); err != nil {
		t.Fatalf("WriteFile(changed) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(paths.KeysDir(identityID), "new.key"), []byte("new"), 0o600); err != nil {
		t.Fatalf("WriteFile(new) error = %v", err)
	}
	if err := os.MkdirAll(paths.KeyTypeRecordsDir(identityID), 0o750); err != nil {
		t.Fatalf("MkdirAll(keytypes) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(paths.KeyTypeRecordsDir(identityID), "new.json"), []byte("new"), 0o600); err != nil {
		t.Fatalf("WriteFile(new keytype) error = %v", err)
	}

	if err := restoreActivationSnapshot(paths, identityID, snapshot); err != nil {
		t.Fatalf("restoreActivationSnapshot() error = %v", err)
	}
	got, err := os.ReadFile(priorPath)
	if err != nil {
		t.Fatalf("ReadFile(prior) error = %v", err)
	}
	if string(got) != "prior" {
		t.Fatalf("prior contents = %q, want prior", got)
	}
	if _, err := os.Stat(filepath.Join(paths.KeysDir(identityID), "new.key")); !os.IsNotExist(err) {
		t.Fatalf("new key stat error = %v, want removed", err)
	}
	if _, err := os.Stat(paths.KeyTypeRecordsDir(identityID)); !os.IsNotExist(err) {
		t.Fatalf("keytypes stat error = %v, want absent", err)
	}

	if err := restoreActivationSnapshot(paths, identityID, snapshot); err != nil {
		t.Fatalf("second restoreActivationSnapshot() error = %v", err)
	}
}

func TestCaptureActivationSnapshotRejectsSymlink(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	if err := os.MkdirAll(paths.KeysDir(identityID), 0o750); err != nil {
		t.Fatalf("MkdirAll(keys) error = %v", err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatalf("WriteFile(target) error = %v", err)
	}
	if err := os.Symlink(target, filepath.Join(paths.KeysDir(identityID), "linked.key")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if _, err := captureActivationSnapshot(paths, identityID, "0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("captureActivationSnapshot(symlink) error = nil, want rejection")
	}
}

func TestSnapshotOwnershipClaimsTemplateFiles(t *testing.T) {
	owned, err := snapshotOwnership([]adminproto.RecoveredReviewEntry{{
		Selector: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		Category: keys.CategoryDSALsig,
		KeyType:  "test.rollback-template.v1",
	}})
	if err != nil {
		t.Fatalf("snapshotOwnership() error = %v", err)
	}
	// A failed activation must be able to roll back everything it writes:
	// the key-type record AND the archive-supplied template. An unowned
	// template would survive rollback and later count as existing keystore
	// material in fingerprint-conflict decisions.
	for _, want := range []string{"test.rollback-template.v1.json", "test.rollback-template.v1.template"} {
		if !slices.Contains(owned["keytypes"], want) {
			t.Fatalf("keytypes ownership %v missing %s", owned["keytypes"], want)
		}
	}
}
