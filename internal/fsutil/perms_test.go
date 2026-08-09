// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileReplacesContentsAndKeepsRestrictiveMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shared.txt")

	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	if err := WriteFile(path, []byte("new")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "new" {
		t.Fatalf("contents = %q, want %q", string(data), "new")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %04o, want 0600", got)
	}
}

func TestWriteFileReplacesNewFileAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fresh.txt")

	if err := WriteFile(path, []byte("hello")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("contents = %q, want %q", string(data), "hello")
	}

	matches, err := filepath.Glob(filepath.Join(dir, "fresh.txt.tmp-*"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("unexpected temp files left behind: %v", matches)
	}
}
