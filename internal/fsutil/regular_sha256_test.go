// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package fsutil

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestRegularFileSHA256RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	data := []byte("content")
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatalf("WriteFile(target) error = %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	got, size, err := RegularFileSHA256(target)
	if err != nil {
		t.Fatalf("RegularFileSHA256(target) error = %v", err)
	}
	want := sha256.Sum256(data)
	if got != hex.EncodeToString(want[:]) || size != int64(len(data)) {
		t.Fatalf("RegularFileSHA256(target) = %q %d", got, size)
	}
	if _, _, err := RegularFileSHA256(link); err == nil {
		t.Fatal("RegularFileSHA256(symlink) error = nil, want rejection")
	}
}

func TestReadRegularFileLimitedRejectsOversizeAndSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	data := []byte("content")
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatalf("WriteFile(target) error = %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	got, mode, err := ReadRegularFileLimited(target, int64(len(data)))
	if err != nil {
		t.Fatalf("ReadRegularFileLimited(exact limit) error = %v", err)
	}
	if string(got) != string(data) || mode != 0o600 {
		t.Fatalf("ReadRegularFileLimited() = %q mode %o", got, mode)
	}
	if _, _, err := ReadRegularFileLimited(target, int64(len(data)-1)); err == nil {
		t.Fatal("ReadRegularFileLimited(oversize) error = nil, want rejection")
	}
	if _, _, err := ReadRegularFileLimited(link, int64(len(data))); err == nil {
		t.Fatal("ReadRegularFileLimited(symlink) error = nil, want rejection")
	}
}
