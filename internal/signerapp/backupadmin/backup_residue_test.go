// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// The startup sweep removes what an interrupted backup creation left behind,
// a partial archive and its verification directory, and leaves published
// backups and files it does not own alone.
func TestStartupSweepRemovesAnInterruptedBackup(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	dir := paths.ProductBackupsDir()
	if err := os.MkdirAll(filepath.Join(dir, backup.CreateValidationPrefix+"123", "apb"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"aplane-backup-20260428-010203.tar.gz.partial", // interrupted
		"aplane-backup-20260427-010203.tar.gz",         // published
		"notes.partial",                                // not an archive's partial name
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	removed, err := CleanupIncompleteBackupImports(paths)
	if err != nil {
		t.Fatalf("CleanupIncompleteBackupImports() = %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, e := range entries {
		left = append(left, e.Name())
	}
	sort.Strings(left)
	want := []string{"aplane-backup-20260427-010203.tar.gz", "notes.partial"}
	if removed != 2 || len(left) != len(want) || left[0] != want[0] || left[1] != want[1] {
		t.Fatalf("removed %d, left %v; want 2 removed and %v left", removed, left, want)
	}
}
