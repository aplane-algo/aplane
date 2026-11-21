// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

// WriteResidue lists what reconciliation's sweep discards, and the copy
// without it is the generation as reconciliation leaves it, with the store
// untouched.
func TestCopyWithoutWriteResidue(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	gen := mintTestGeneration(t, paths, testGenA, map[string]string{
		"keytypes/test.kept.v1.json": "{}",
		// A legitimate name that merely contains ".tmp-" is not residue.
		"keytypes/custom.tmp-v2.template": "kept",
	})
	for _, relative := range []string{
		storepaths.GenerationSealName + ".tmp-123456",
		"keytypes/test.kept.v1.json.tmp-123",
		"keys/ADDR.key.tmp-998877",
	} {
		if err := os.WriteFile(filepath.Join(gen.Dir(), filepath.FromSlash(relative)), []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	residue, err := WriteResidue(gen)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{storepaths.GenerationSealName + ".tmp-123456", "keys/ADDR.key.tmp-998877", "keytypes/test.kept.v1.json.tmp-123"}
	if !reflect.DeepEqual(residue, want) {
		t.Fatalf("WriteResidue() = %q, want %q", residue, want)
	}
	before := treeFiles(t, gen.Dir())

	copied, err := CopyWithoutWriteResidue(gen, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCurrent(copied); err != nil {
		t.Fatalf("ValidateCurrent(copy) error = %v", err)
	}
	got := treeFiles(t, copied.Dir())
	for _, relative := range residue {
		delete(before, relative)
	}
	if !reflect.DeepEqual(got, before) {
		t.Fatalf("copy = %v, want the generation without its residue %v", got, before)
	}
	if after := treeFiles(t, gen.Dir()); len(after) != len(before)+len(residue) {
		t.Fatalf("the source generation changed: %v", after)
	}
	report, err := reconcileSelected(paths, testGenA, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(treeFiles(t, gen.Dir()), got) {
		t.Fatalf("reconciled generation = %v, want the copy %v", treeFiles(t, gen.Dir()), got)
	}
	if len(report.DiscardedStaging) != len(residue) {
		t.Fatalf("reconcile discarded %v, want %d entries", report.DiscardedStaging, len(residue))
	}
}

func treeFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(dir, path)
		files[filepath.ToSlash(relative)] = string(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}
