// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestManagedCredentialExtensionsHaveOneOwner prevents filesystem consumers
// from recreating the account/sentry extension table outside internal/keys.
func TestManagedCredentialExtensionsHaveOneOwner(t *testing.T) {
	root := filepath.Join("..", "..")
	extensions := map[string]bool{
		"." + "key": true,
		"." + "sen": true,
	}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "temp", "vendor", "node_modules":
				if path != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if strings.HasPrefix(filepath.ToSlash(rel), "internal/keys/") {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err == nil && extensions[value] {
				t.Errorf("%s owns managed credential extension literal %q; use internal/keys", rel, value)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("scan managed credential extension ownership: %v", err)
	}
}
