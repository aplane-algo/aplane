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

func TestPruneDeletedArchiveKeepsPolicyPairsTogether(t *testing.T) {
	const doc = "deleted/policies/MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ.json"
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{doc: "{}", doc + ".hmac": "{}"})
	for _, selection := range [][]string{{doc}, {doc + ".hmac"}} {
		if _, err := PruneDeletedArchive(gen, selection); err == nil {
			t.Fatalf("PruneDeletedArchive(%v) split a policy pair", selection)
		}
	}
	for _, member := range []string{doc, doc + ".hmac"} {
		if _, err := os.Stat(filepath.Join(gen.Dir(), member)); err != nil {
			t.Fatalf("refused prune changed %s: %v", member, err)
		}
	}
	if _, err := PruneDeletedArchive(gen, []string{doc, doc + ".hmac"}); err != nil {
		t.Fatalf("PruneDeletedArchive(pair) error = %v", err)
	}
	// A lone survivor of an interrupted prune can still be removed.
	if err := os.WriteFile(filepath.Join(gen.Dir(), doc+".hmac"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PruneDeletedArchive(gen, []string{doc + ".hmac"}); err != nil {
		t.Fatalf("PruneDeletedArchive(orphan sidecar) error = %v", err)
	}
}

// An archived source token file is pruned alone: it has no partner. A name
// in that namespace without the token file extension is refused.
func TestPruneDeletedArchiveAcceptsArchivedSourceTokens(t *testing.T) {
	const tokens = "deleted/source_tokens/MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ.enc"
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{tokens: "sealed"})
	for _, invalid := range []string{
		"deleted/source_tokens/MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ.json",
		"source_tokens/MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ.enc",
		"deleted/source_tokens/../keys/A.key",
	} {
		if _, err := PruneDeletedArchive(gen, []string{invalid}); err == nil {
			t.Fatalf("PruneDeletedArchive(%q) accepted it", invalid)
		}
	}
	results, err := PruneDeletedArchive(gen, []string{tokens})
	if err != nil || len(results) != 1 || results[0].EncodedBytes != int64(len("sealed")) {
		t.Fatalf("PruneDeletedArchive(source tokens) = (%+v, %v)", results, err)
	}
	if _, err := os.Stat(filepath.Join(gen.Dir(), tokens)); !os.IsNotExist(err) {
		t.Fatalf("pruned source token file survived: %v", err)
	}
}

func TestListDeletedArchiveReportsEveryNamespaceSorted(t *testing.T) {
	const policy = "deleted/policies/MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ.json"
	const tokens = "deleted/source_tokens/MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ.enc"
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{
		"deleted/keys/B.cos":             "bb",
		"deleted/keys/A.key":             "a",
		"deleted/keytypes/x.template":    "template",
		policy:                           "{}",
		policy + ".hmac":                 "hmac!",
		tokens:                           "tokens",
		"deleted/keytypes/a.v1.template": "t",
		"deleted/keys/C.key":             "ccc",
	})
	items, usage, err := ListDeletedArchive(gen)
	if err != nil {
		t.Fatal(err)
	}
	want := []DeletedArchiveEntry{
		{"deleted/keys/A.key", 1},
		{"deleted/keys/B.cos", 2},
		{"deleted/keys/C.key", 3},
		{"deleted/keytypes/a.v1.template", 1},
		{"deleted/keytypes/x.template", 8},
		{policy, 2},
		{policy + ".hmac", 5},
		{tokens, 6},
	}
	if len(items) != len(want) {
		t.Fatalf("items = %+v", items)
	}
	for i := range want {
		if items[i] != want[i] {
			t.Fatalf("items[%d] = %+v, want %+v", i, items[i], want[i])
		}
	}
	if usage != (DeletedArchiveUsage{Entries: 8, EncodedBytes: 28}) {
		t.Fatalf("usage = %+v", usage)
	}

	if err := os.Symlink("A.key", filepath.Join(gen.DeletedKeyTypeRecordsDir(), "link.template")); err != nil {
		t.Fatal(err)
	}
	items, usage, err = ListDeletedArchive(gen)
	if err == nil || items != nil || usage != (DeletedArchiveUsage{Entries: 4, EncodedBytes: 7}) {
		t.Fatalf("ListDeletedArchive() with a link = (%+v, %+v, %v)", items, usage, err)
	}
}
