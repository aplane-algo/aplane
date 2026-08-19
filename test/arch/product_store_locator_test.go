// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var productStoreLocatorRoots = []string{
	"cmd/apadmin",
	"cmd/appass",
	"cmd/apsigner",
	"cmd/apstore",
	"internal/backup",
	"internal/genstore",
	"internal/keygen",
	"internal/keymgmt",
	"internal/keys",
	"internal/keystore",
	"internal/keytypestate",
	"internal/noderole",
	"internal/policy",
	"internal/rotationinventory",
	"internal/sentry/sentryrefs",
	"internal/signerapp",
	"internal/storeinit",
	"internal/storepass",
	"internal/storepaths",
	"internal/templatelibrary",
	"internal/templatestore",
	"internal/tokenfile",
}

// TestProductStoreLocatorInventoryBaseline makes the pre-simplification
// identity-locator surface reproducible. The final slice changes this from an
// inventory to a zero-surface architecture guard.
func TestProductStoreLocatorInventoryBaseline(t *testing.T) {
	locators := productStoreLocatorInventory(t)
	if len(locators) == 0 {
		t.Fatal("identity locator inventory is unexpectedly empty before simplification")
	}
	t.Logf("product-store identity locator declarations (%d):\n%s", len(locators), strings.Join(locators, "\n"))
}

func productStoreLocatorInventory(t *testing.T) []string {
	t.Helper()
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	var inventory []string
	for _, relRoot := range productStoreLocatorRoots {
		walkRoot := filepath.Join(root, filepath.FromSlash(relRoot))
		err := filepath.WalkDir(walkRoot, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Type.Params == nil {
					continue
				}
				for _, field := range fn.Type.Params.List {
					ident, isString := field.Type.(*ast.Ident)
					if !isString || ident.Name != "string" {
						continue
					}
					for _, name := range field.Names {
						if name.Name == "identityID" {
							rel, err := filepath.Rel(root, path)
							if err != nil {
								return err
							}
							inventory = append(inventory, fmt.Sprintf("%s:%s", filepath.ToSlash(rel), fn.Name.Name))
						}
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("inventory %s: %v", relRoot, err)
		}
	}
	sort.Strings(inventory)
	return inventory
}
