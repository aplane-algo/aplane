// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyexport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
)

// writeExport writes a complete export into a new directory and returns its
// document paths.
func writeExport(t *testing.T) []string {
	t.Helper()
	docs := []Document{exportDoc(policy.DefaultKey, "{}"), exportDoc(exportTestKey, "{\"k\":1}")}
	paths, err := contextView(t, exportSet(docs...)).write(filepath.Join(t.TempDir(), "export"), docs)
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

func bareFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "draft.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDiscoverWithoutAnExport(t *testing.T) {
	selected, err := Discover([]string{bareFile(t), "-"}, "")
	if err != nil || selected != nil {
		t.Fatalf("Discover() = %v, %v; want no context", selected, err)
	}
}

func TestDiscoverUsesAnOverrideForEveryFile(t *testing.T) {
	exported := writeExport(t)
	override := filepath.Join(filepath.Dir(exported[0]), ContextDir, ContextFile)
	selected, err := Discover([]string{bareFile(t), "-"}, override)
	if err != nil || selected == nil || selected.Path != override {
		t.Fatalf("Discover() = %v, %v; want the override", selected, err)
	}
}

func TestDiscoverRefusesWhatIsNotOneCompleteContext(t *testing.T) {
	first, second := writeExport(t), writeExport(t)

	damaged := writeExport(t)
	if err := os.WriteFile(filepath.Join(filepath.Dir(damaged[0]), ContextDir, ContextFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	notDir := bareFile(t)
	if err := os.WriteFile(filepath.Join(filepath.Dir(notDir), ContextDir), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	linked := writeExport(t)
	contextPath := filepath.Join(filepath.Dir(linked[0]), ContextDir, ContextFile)
	moved := contextPath + ".real"
	if err := os.Rename(contextPath, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, contextPath); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		files []string
		want  string
	}{
		"two exports":              {[]string{first[0], second[0]}, "different exports"},
		"an export and a draft":    {[]string{first[0], bareFile(t)}, "not from the export"},
		"an export and stdin":      {[]string{"-", first[0]}, "not from the export"},
		"a damaged context":        {[]string{damaged[0]}, "context file"},
		"a context path not a dir": {[]string{notDir}, "not a directory"},
		"a linked context":         {[]string{linked[0]}, "not a regular file"},
	} {
		if _, err := Discover(tc.files, ""); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Discover() error = %v, want one naming %q", name, err, tc.want)
		}
	}
}

// appolicy keeps saved cases in .appolicy too: without a context file or a
// marker, the directory is not an export.
func TestACasesDirectoryIsNotAnExport(t *testing.T) {
	draft := bareFile(t)
	if err := os.Mkdir(filepath.Join(filepath.Dir(draft), ContextDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if selected, err := Discover([]string{draft}, ""); err != nil || selected != nil {
		t.Fatalf("Discover() = %v, %v; want no context", selected, err)
	}
	if selected, err := ForDir(filepath.Dir(draft), ""); err != nil || selected != nil {
		t.Fatalf("ForDir() = %v, %v; want no context", selected, err)
	}
	exported := writeExport(t)
	if selected, err := ForDir(filepath.Dir(exported[0]), ""); err != nil || selected == nil {
		t.Fatalf("ForDir(export) = %v, %v", selected, err)
	}
}

func TestDiscoverAcceptsAnExportsOwnFilesTogether(t *testing.T) {
	exported := writeExport(t)
	added := filepath.Join(filepath.Dir(exported[0]), "new-key.json")
	if err := os.WriteFile(added, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	selected, err := Discover(append(exported, added), "")
	if err != nil || selected == nil {
		t.Fatalf("Discover() = %v, %v; want the export's context for a file added to it too", selected, err)
	}
}
