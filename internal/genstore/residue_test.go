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

// WriteResidue lists exactly what reconciliation's sweep discards, by path,
// and leaves the generation alone.
func TestWriteResidueIsWhatReconciliationDiscards(t *testing.T) {
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
	for _, relative := range residue {
		if _, err := os.Stat(filepath.Join(gen.Dir(), filepath.FromSlash(relative))); err != nil {
			t.Fatalf("WriteResidue() touched %s: %v", relative, err)
		}
	}
	report, err := reconcileSelected(paths, testGenA, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(report.DiscardedStaging, []string{storepaths.GenerationSealName + ".tmp-123456", "ADDR.key.tmp-998877", "test.kept.v1.json.tmp-123"}) {
		t.Fatalf("reconcile discarded %q, want the listed residue", report.DiscardedStaging)
	}
	for _, relative := range residue {
		if _, err := os.Stat(filepath.Join(gen.Dir(), filepath.FromSlash(relative))); !os.IsNotExist(err) {
			t.Fatalf("%s after reconciliation: %v, want gone", relative, err)
		}
	}
	if _, err := os.Stat(filepath.Join(gen.KeyTypeRecordsDir(), "custom.tmp-v2.template")); err != nil {
		t.Fatalf("a record whose name contains .tmp- was discarded: %v", err)
	}
}
