// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templatelibrary

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/library/retired"
	"github.com/aplane-algo/aplane/lsig/falcon1024"
)

func retiredFiles(t *testing.T) []string {
	t.Helper()
	entries, err := retired.FS.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".yaml") {
			names = append(names, entry.Name())
		}
	}
	if len(names) != 5 {
		t.Fatalf("retired templates = %v, want five", names)
	}
	return names
}

func TestRetiredTemplateReimportMatchesInstalledCopy(t *testing.T) {
	falcon.RegisterClient()
	keyring := cryptotest.Keyring(t, testMasterKey())
	for _, name := range retiredFiles(t) {
		t.Run(name, func(t *testing.T) {
			paths := newLibraryTestPaths(t)
			marked, err := retired.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			_, unmarked, found := strings.Cut(string(marked), "schema_version:")
			if !found {
				t.Fatal("no schema_version")
			}
			installedCopy := mustParseYAML(t, name, []byte("schema_version:"+unmarked))
			if _, err := InstallParsed(paths, installedCopy, keyring); err != nil {
				t.Fatalf("install the copy an existing store holds: %v", err)
			}

			result, err := InstallParsed(paths, mustParseYAML(t, name, marked), keyring)
			if err != nil {
				t.Fatalf("re-import the marked file: %v", err)
			}
			if !result.AlreadyExists {
				t.Fatalf("re-import = %+v, want AlreadyExists", result)
			}
		})
	}
}

func TestRetiredTemplatesStayOutOfTheListingUntilInstalled(t *testing.T) {
	falcon.RegisterClient()
	paths := newLibraryTestPaths(t)
	if err := EnsureLibraryDir(paths); err != nil {
		t.Fatal(err)
	}
	retiredDir := filepath.Join(filepath.Dir(paths.TemplateLibraryDir()), "retired")
	if err := os.MkdirAll(retiredDir, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "aplane.corridor.v1.yaml"
	data, err := retired.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(retiredDir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	items, err := List(paths)
	if err != nil {
		t.Fatal(err)
	}
	if item := findLibraryItem(items, "aplane.corridor.v1"); item != nil {
		t.Fatalf("retired file listed: %+v", *item)
	}
	if _, _, err := FindLibraryYAML(paths, TemplateRef{KeyType: "aplane.corridor.v1", TemplateType: templatestore.TemplateTypeComposed}); !os.IsNotExist(err) && !strings.Contains(err.Error(), "no entry") {
		t.Fatalf("FindLibraryYAML() error = %v, want no entry", err)
	}

	parsed, err := ParseFile(path)
	if err != nil {
		t.Fatalf("expert import reads a retired file: %v", err)
	}
	if _, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, testMasterKey())); err != nil {
		t.Fatal(err)
	}
	items, err = List(paths)
	if err != nil {
		t.Fatal(err)
	}
	item := findLibraryItem(items, "aplane.corridor.v1")
	if item == nil || !item.Installed || !item.Enabled || item.SourcePath != "" {
		t.Fatalf("installed retired template = %+v, want installed, enabled, and without a library source", item)
	}
}
