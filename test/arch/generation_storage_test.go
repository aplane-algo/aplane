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
	"internal/storepass",
	"internal/signerapp/backupadmin",
	"internal/signerapp/productruntime",
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
			if permittedNonStoreHardlink(path, root, file, call.Pos()) {
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

// permittedNonStoreHardlink records narrow exceptions inside otherwise
// store-owning packages. Backup export links a fully written client-side
// staging file to its operator-selected destination as an atomic no-replace
// fallback; neither pathname is part of the signer store or a generation.
func permittedNonStoreHardlink(path, root string, file *ast.File, pos token.Pos) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil || filepath.ToSlash(rel) != "internal/apadminapp/store.go" {
		return false
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "publishBackupExportNoReplaceWith" {
			continue
		}
		return function.Pos() <= pos && pos <= function.End()
	}
	return false
}

// TestRetiredRootStorePathAPIsStayDeleted prevents pre-generation root-level
// key and key-type helpers from returning as a compatibility shim.
func TestRetiredRootStorePathAPIsStayDeleted(t *testing.T) {
	root := filepath.Join("..", "..")
	retired := map[string]struct{}{
		"LegacyKeysDir":           {},
		"LegacyKeyTypeRecordsDir": {},
		"LegacyKeyTypeRecord":     {},
		"LegacyKeyTypeTemplate":   {},
	}
	path := filepath.Join(root, "internal", "storepaths", "paths.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if _, found := retired[function.Name.Name]; found {
			t.Errorf("%s: retired root store path API %s returned", fset.Position(function.Pos()), function.Name.Name)
		}
	}
}

// TestRetiredStoreCommitArtifactsStayDeleted prevents either half of the old
// two-record commit protocol from returning to production code.
func TestRetiredStoreCommitArtifactsStayDeleted(t *testing.T) {
	root := filepath.Join("..", "..")
	allowed := filepath.ToSlash("internal/genstore/root_commit.go") // explicit initialization rejection
	for _, retired := range []string{"CURRENT", "keyring.enc", "rotation.snapshot.enc", "rotation.baseline.enc"} {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				switch entry.Name() {
				case ".git", "temp", "vendor", "node_modules", "docs":
					if path != root {
						return filepath.SkipDir
					}
				}
				return nil
			}
			if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			if filepath.ToSlash(rel) == allowed {
				return nil
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if strings.Contains(string(data), `"`+retired+`"`) {
				t.Errorf("%s contains retired store artifact %q", path, retired)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
