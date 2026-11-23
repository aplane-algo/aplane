// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build linux || darwin

package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestOpenRegularFileSymlinkPreservesELOOP(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, _, err := ReadRegularFileLimited(link, 64)
	if !errors.Is(err, ErrNotRegularFile) || !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("ReadRegularFileLimited(symlink) error = %v, want both ErrNotRegularFile and syscall.ELOOP", err)
	}
}
