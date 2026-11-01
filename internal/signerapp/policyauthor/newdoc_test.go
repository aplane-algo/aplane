// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
)

func TestStartingPointsBuildDocumentsForTheNewKey(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "ops.json", fixture(t, "signer_key_full.json"))
	writeFile(t, dir, "c.json", fixture(t, "cosigner_default.json"))
	w, _ := Open(dir)

	signer := w.StartingPoints(noderole.RoleSigner)
	if len(signer) != 2 || !strings.Contains(signer[0].Label, "shipped signer default") || !strings.Contains(signer[1].Label, "ops.json") {
		t.Fatalf("signer starting points: %+v", signer)
	}
	for _, sp := range signer {
		d, err := sp.Draft(testSignerKey2)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := d.Canonical()
		if _, err := policy.DecodePolicyV1(out, testSignerKey2, noderole.RoleSigner); err != nil {
			t.Fatalf("%s: %v", sp.Label, err)
		}
	}

	cosigner := w.StartingPoints(noderole.RoleCosigner)
	presets := 0
	for _, sp := range cosigner {
		d, err := sp.Draft(testWitnessKeyID)
		if err != nil {
			t.Fatalf("%s: %v", sp.Label, err)
		}
		if key, _ := d.TopLevelString("key"); key != testWitnessKeyID {
			t.Fatalf("%s: key %q", sp.Label, key)
		}
		if strings.HasPrefix(sp.Label, "Preset ") {
			presets++
		}
	}
	if presets < 3 {
		t.Fatalf("only %d cosigner presets offered", presets)
	}
}

func TestCheckNewKeyAndNewFilePath(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "default.json", fixture(t, "signer_default.json"))
	w, _ := Open(dir)
	if err := w.CheckNewKey(noderole.RoleSigner, testSignerKey); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"default", "notakey", testWitnessKeyID} {
		if err := w.CheckNewKey(noderole.RoleSigner, bad); err == nil {
			t.Errorf("key %q accepted", bad)
		}
	}
	if err := w.CheckNewKey(noderole.RoleCosigner, testWitnessKeyID); err != nil {
		t.Fatal(err)
	}
	if p, err := w.NewFilePath("treasury.json"); err != nil || p != filepath.Join(dir, "treasury.json") {
		t.Fatalf("path %q, %v", p, err)
	}
	for _, bad := range []string{"default.json", "sub/x.json", "x.txt", ""} {
		if _, err := w.NewFilePath(bad); err == nil {
			t.Errorf("file name %q accepted", bad)
		}
	}
	// A workspace opened on a file creates beside it.
	file := writeFile(t, t.TempDir(), "only.json", fixture(t, "signer_default.json"))
	single, _ := Open(file)
	if p, _ := single.NewFilePath("k.json"); p != filepath.Join(filepath.Dir(file), "k.json") {
		t.Fatalf("path %q", p)
	}
	added := single.Add(&File{Path: filepath.Join(filepath.Dir(file), "k.json")})
	if len(added.Files) != 2 || len(added.Paths) != 2 || len(single.Files) != 1 {
		t.Fatalf("add: %d files, paths %v", len(added.Files), added.Paths)
	}
}
