// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
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

func TestOperatorGuidanceUsesApadminForLiveOperations(t *testing.T) {
	root := filepath.Join("..", "..")
	retired := regexp.MustCompile(`\bapstore(?:\s+-d\s+(?:"[^"]*"|'[^']*'|\S+))?\s+(?:(?:backup|restore|changepass|template|keytype|sentry|endpoint)\b|generations\s+list\b)`)
	historical := map[string]bool{
		filepath.Join("docs", "PHASE3_ONBOARDING.md"):         true,
		filepath.Join("docs", "PROPOSAL_KEYTERM_ROTATION.md"): true,
	}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "bin", "node_modules", "temp":
				return filepath.SkipDir
			}
			return nil
		}
		if path == filepath.Join(root, "test", "arch", "admin_binary_boundary_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if historical[rel] {
			return nil
		}
		ext := filepath.Ext(path)
		if ext == "" && entry.Name() != "Makefile" {
			return nil
		}
		if ext != ".go" && ext != ".md" && ext != ".sh" && ext != ".yml" && ext != ".yaml" && ext != ".example" && ext != "" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if match := retired.Find(data); match != nil {
			t.Errorf("%s retains retired live command %q", rel, match)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
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
