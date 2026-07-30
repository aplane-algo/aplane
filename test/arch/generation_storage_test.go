// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// storeOwningPackages are the packages that read or write identity-store
// content. Link-based idioms elsewhere (client caches, ceremony artifacts,
// token files) never touch generations and stay out of scope.
var storeOwningPackages = []string{
	"internal/genstore",
	"internal/storeinit",
	"internal/storepaths",
	"internal/fsutil",
	"internal/keys",
	"internal/keystore",
	"internal/keymgmt",
	"internal/keytypestate",
	"internal/templatestore",
	"internal/templatelibrary",
	"internal/defaultkeytypes",
	"internal/backup",
	"internal/rotationinventory",
	"internal/storepass",
	"internal/signerapp/backupadmin",
	"internal/signerapp/identity",
	"internal/signerapp/daemon",
	"cmd/apstore",
}

// TestNoHardlinksInStoreCode enforces docs/ARCH_GENERATIONS.md §1:
// generations are built from independent copies, never hardlinks. A shared
// inode would let a later in-place write mutate a prior (sealed) generation.
func TestNoHardlinksInStoreCode(t *testing.T) {
	root := filepath.Join("..", "..")
	inScope := func(path string) bool {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return false
		}
		rel = filepath.ToSlash(rel)
		for _, pkg := range storeOwningPackages {
			if strings.HasPrefix(rel, pkg+"/") || filepath.Dir(rel) == pkg {
				return true
			}
		}
		return false
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
		if !inScope(path) {
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Link" {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok || pkg.Name != "os" {
				return true
			}
			t.Errorf("%s: os.Link is forbidden (independent copies only; a hardlink shares an inode with a sealed generation)",
				fset.Position(call.Pos()))
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk error = %v", err)
	}
}
