// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestApstoreHasNoLiveAdminTransport(t *testing.T) {
	root := filepath.Join("..", "..", "cmd", "apstore")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(root, entry.Name())
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range parsed.Imports {
			name, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if name == "github.com/aplane-algo/aplane/internal/transport" {
				t.Errorf("%s imports the live admin transport", entry.Name())
			}
		}
	}

	assertFileOmits(t, filepath.Join(root, "main.go"), "--ipc-path", "adminSocketPath")
	assertFileOmits(t, filepath.Join(root, "dispatch.go"),
		`case "backup":`, `case "restore":`, `case "changepass":`,
		`case "template":`, `case "keytype":`, `case "sentry":`, `case "endpoint":`,
	)
	assertFileOmits(t, filepath.Join(root, "usage.go"),
		"apstore backup", "apstore restore", "apstore changepass", "apstore template",
		"apstore keytype", "apstore sentry", "apstore endpoint", "apstore generations list",
	)
}

func assertFileOmits(t *testing.T, path string, forbidden ...string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range forbidden {
		if strings.Contains(string(data), value) {
			t.Errorf("%s retains retired live-admin surface %q", filepath.Base(path), value)
		}
	}
}
