// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"os"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestManagedArchiveNameTime(t *testing.T) {
	for name, want := range map[string]time.Time{
		"aplane-backup-20261102-070725.677012380.tar.gz": time.Date(2026, 11, 2, 7, 7, 25, 677012380, time.UTC),
		"aplane-backup-20260423-010203.tar.gz":           time.Date(2026, 4, 23, 1, 2, 3, 0, time.UTC),
	} {
		if got, ok := ManagedArchiveNameTime(name); !ok || !got.Equal(want) {
			t.Errorf("ManagedArchiveNameTime(%q) = %v, %v; want %v", name, got, ok, want)
		}
	}
	for _, name := range []string{"lab-signer.tar.gz", "aplane-backup-older.tar.gz", "aplane-backup-20260423-010203.tgz"} {
		if _, ok := ManagedArchiveNameTime(name); ok {
			t.Errorf("ManagedArchiveNameTime(%q) parsed a time", name)
		}
	}
}

func TestListManagedBackupsOrdersByNameTimeOverFileTime(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	if err := os.MkdirAll(paths.ProductBackupsDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	// The older backup was copied in last, so its file is the newer one.
	older := BuildManagedArchivePath(paths, "20260101-000000.000000000")
	newer := BuildManagedArchivePath(paths, "20260601-000000.000000000")
	for _, path := range []string{newer, older} {
		if err := os.WriteFile(path, []byte(path), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(newer, past, past); err != nil {
		t.Fatal(err)
	}
	items, err := ListManagedBackups(paths)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Path != newer || items[1].Path != older {
		t.Fatalf("order = %v; want the newer name first", items)
	}
	if want := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC); !items[0].BestCreatedAt().Equal(want) {
		t.Fatalf("BestCreatedAt() = %v, want %v from the name", items[0].BestCreatedAt(), want)
	}
}
