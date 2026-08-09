// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package ipcbind

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateBindPathAllowsMissingSocketInPrivateDir(t *testing.T) {
	dir := privateTempDir(t)

	if err := ValidateBindPath(filepath.Join(dir, "apsigner.sock")); err != nil {
		t.Fatalf("ValidateBindPath() error = %v, want nil", err)
	}
}

func TestValidateBindPathRejectsSymlink(t *testing.T) {
	dir := privateTempDir(t)
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "apsigner.sock")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	err := ValidateBindPath(link)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("ValidateBindPath() error = %v, want symlink rejection", err)
	}
}

func TestValidateBindPathRejectsTmpDirectory(t *testing.T) {
	err := ValidateBindPath("/tmp/aplane-apsigner.sock")
	if err == nil || !strings.Contains(err.Error(), "world-writable directory") {
		t.Fatalf("ValidateBindPath(/tmp) error = %v, want world-writable rejection", err)
	}
}

func TestValidateBindPathRejectsWorldWritableDirectory(t *testing.T) {
	dir := privateTempDir(t)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod temp dir: %v", err)
	}

	err := ValidateBindPath(filepath.Join(dir, "apsigner.sock"))
	if err == nil || !strings.Contains(err.Error(), "world-writable directory") {
		t.Fatalf("ValidateBindPath() error = %v, want world-writable rejection", err)
	}
}

func TestValidatePrivateRuntimeBindPathRejectsGroupWritableDirectory(t *testing.T) {
	dir := privateTempDir(t)
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatalf("chmod temp dir: %v", err)
	}

	err := ValidatePrivateRuntimeBindPath(filepath.Join(dir, "apsigner.sock"))
	if err == nil || !strings.Contains(err.Error(), "group-writable") {
		t.Fatalf("ValidatePrivateRuntimeBindPath() error = %v, want group-writable rejection", err)
	}
}

func TestValidatePrivateRuntimeBindPathAcceptsGroupTraversableDirectory(t *testing.T) {
	dir := privateTempDir(t)
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatalf("chmod temp dir: %v", err)
	}

	if err := ValidatePrivateRuntimeBindPath(filepath.Join(dir, "apsigner.sock")); err != nil {
		t.Fatalf("ValidatePrivateRuntimeBindPath() error = %v, want nil", err)
	}
}

func TestValidateBindPathRejectsMissingParent(t *testing.T) {
	dir := privateTempDir(t)
	err := ValidateBindPath(filepath.Join(dir, "missing", "apsigner.sock"))
	if err == nil || !strings.Contains(err.Error(), "failed to inspect") {
		t.Fatalf("ValidateBindPath() error = %v, want missing-parent rejection", err)
	}
}

func TestValidateBindPathRejectsExistingRegularFile(t *testing.T) {
	dir := privateTempDir(t)
	path := filepath.Join(dir, "apsigner.sock")
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	err := ValidateBindPath(path)
	if err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("ValidateBindPath() error = %v, want non-socket rejection", err)
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp(".", "ipcbind-test-*")
	if err != nil {
		t.Fatalf("create private temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o700)
		_ = os.RemoveAll(dir)
	})
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod temp dir: %v", err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("abs temp dir: %v", err)
	}
	return abs
}
