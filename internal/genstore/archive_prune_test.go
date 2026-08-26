// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestPruneDeletedArchiveUsesExplicitClosedSelection(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{
		"deleted/keys/A.key":                "a",
		"deleted/keytypes/example.template": "template",
	})
	items, usage, err := ListDeletedArchive(gen)
	if err != nil || len(items) != 2 || usage.Entries != 2 {
		t.Fatalf("ListDeletedArchive() = (%+v, %+v, %v)", items, usage, err)
	}
	results, err := PruneDeletedArchive(gen, []string{"deleted/keys/A.key"})
	if err != nil || len(results) != 1 || results[0].EncodedBytes != 1 {
		t.Fatalf("PruneDeletedArchive() = (%+v, %v)", results, err)
	}
	if _, err := os.Stat(filepath.Join(gen.DeletedKeysDir(), "A.key")); !os.IsNotExist(err) {
		t.Fatalf("selected entry survived: %v", err)
	}
	if _, err := os.Stat(filepath.Join(gen.DeletedKeyTypeRecordsDir(), "example.template")); err != nil {
		t.Fatalf("unselected entry changed: %v", err)
	}
	results, err = PruneDeletedArchive(gen, []string{"deleted/keys/A.key"})
	if err != nil || !results[0].AlreadyAbsent {
		t.Fatalf("retry = (%+v, %v)", results, err)
	}
}

func TestPruneDeletedArchiveRejectsTraversalBeforeMutation(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{"deleted/keys/A.key": "a"})
	if _, err := PruneDeletedArchive(gen, []string{"deleted/keys/A.key", "deleted/keys/../A.key"}); err == nil {
		t.Fatal("PruneDeletedArchive accepted traversal")
	}
	if _, err := os.Stat(filepath.Join(gen.DeletedKeysDir(), "A.key")); err != nil {
		t.Fatalf("selection validation partially mutated archive: %v", err)
	}
}
