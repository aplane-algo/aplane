// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientregistry

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/fsutil"
)

func TestLoadMissingFileIsEmpty(t *testing.T) {
	reg, err := Load(filepath.Join(t.TempDir(), "missing"))
	if err != nil || reg.Len() != 0 {
		t.Fatalf("Load(missing) = %v, %v", reg, err)
	}
}

func TestPublishThenLoadRoundTripsAndIsPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".ssh", "authorized_keys")
	reg, _ := Parse(nil)
	reg, _ = reg.WithKey(testKey(t), "one")

	if err := Publish(path, reg); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("registry mode = %o, want 0600", info.Mode().Perm())
	}
	loaded, err := Load(path)
	if err != nil || !bytes.Equal(loaded.Marshal(), reg.Marshal()) {
		t.Fatalf("Load() = %v, %v", loaded, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestLoadRejectsBadFileWithPathAndLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(path, []byte("restrict "+keyLine(testKey(t), "")), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("Load() error = %v, want path and line", err)
	}
}

// A directory fsync failure after the rename is reported, not swallowed: the
// caller must not acknowledge a change that may not survive a crash.
func TestPublishReportsDirectorySyncFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	reg, _ := Parse(nil)
	reg, _ = reg.WithKey(testKey(t), "one")

	fsutil.TestHook = func(op fsutil.HookOp, _ string) error {
		if op == fsutil.OpDirSync {
			return errors.New("injected dir sync failure")
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()

	err := Publish(path, reg)
	if err == nil || !strings.Contains(err.Error(), "injected dir sync failure") {
		t.Fatalf("Publish() error = %v, want the directory sync failure", err)
	}
	// The rename happened before the sync, so the file is in place.
	loaded, loadErr := Load(path)
	if loadErr != nil || !bytes.Equal(loaded.Marshal(), reg.Marshal()) {
		t.Fatalf("Load() after failed sync = %v, %v", loaded, loadErr)
	}
}

// Publish refuses to replace a symlinked registry.
func TestPublishRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "authorized_keys")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	reg, _ := Parse(nil)
	if err := Publish(path, reg); err == nil {
		t.Fatal("Publish() over a symlink succeeded, want refusal")
	}
}
