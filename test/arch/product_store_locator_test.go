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

var allowedCompatibilityIdentityParameters = map[string]bool{}

var allowedCompatibilityIdentityFields = map[string]bool{}

var forbiddenProductStoreFunctions = map[string]bool{
	"BuildIdentityRuntime":           true,
	"CurrentProductIdentityID":       true,
	"IsCurrentProductIdentity":       true,
	"RequireCurrentProductIdentity":  true,
	"WithIdentityInspection":         true,
	"WithIdentityMutation":           true,
	"withIdentityStoreInspection":    true,
	"withIdentityStoreMutation":      true,
	"tryWithIdentityStoreInspection": true,
}

func TestFixedProductStoreBoundary(t *testing.T) {
	inventory := productStoreIdentityInventory(t)
	if len(inventory.unexpectedParameters) != 0 {
		t.Fatalf("product-store identity locator parameters regrew:\n%s", strings.Join(inventory.unexpectedParameters, "\n"))
	}
	if len(inventory.unexpectedFields) != 0 {
		t.Fatalf("product-store identity fields regrew outside compatibility boundaries:\n%s", strings.Join(inventory.unexpectedFields, "\n"))
	}
	if len(inventory.forbiddenFunctions) != 0 {
		t.Fatalf("retired product-store APIs regrew:\n%s", strings.Join(inventory.forbiddenFunctions, "\n"))
	}
	if len(inventory.runtimeIDMethods) != 0 {
		t.Fatalf("runtime identity accessors regrew:\n%s", strings.Join(inventory.runtimeIDMethods, "\n"))
	}
	assertExactInventory(t, "compatibility identity parameters", inventory.allowedParameters, allowedCompatibilityIdentityParameters)
	assertExactInventory(t, "compatibility identity fields", inventory.allowedFields, allowedCompatibilityIdentityFields)
}

type productStoreInventory struct {
	allowedParameters    []string
	unexpectedParameters []string
	allowedFields        []string
	unexpectedFields     []string
	forbiddenFunctions   []string
	runtimeIDMethods     []string
}

func productStoreIdentityInventory(t *testing.T) productStoreInventory {
	t.Helper()
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	var inventory productStoreInventory
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
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			relPath := filepath.ToSlash(rel)
			for _, decl := range file.Decls {
				switch typed := decl.(type) {
				case *ast.FuncDecl:
					inventoryFunction(relPath, typed, &inventory)
				case *ast.GenDecl:
					inventoryIdentityFields(relPath, typed, &inventory)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("inventory %s: %v", relRoot, err)
		}
	}
	sort.Strings(inventory.allowedParameters)
	sort.Strings(inventory.unexpectedParameters)
	sort.Strings(inventory.allowedFields)
	sort.Strings(inventory.unexpectedFields)
	sort.Strings(inventory.forbiddenFunctions)
	sort.Strings(inventory.runtimeIDMethods)
	return inventory
}

func inventoryFunction(path string, fn *ast.FuncDecl, inventory *productStoreInventory) {
	key := fmt.Sprintf("%s:%s", path, fn.Name.Name)
	if forbiddenProductStoreFunctions[fn.Name.Name] {
		inventory.forbiddenFunctions = append(inventory.forbiddenFunctions, key)
	}
	if fn.Name.Name == "ID" && receiverTypeName(fn.Recv) == "Runtime" {
		inventory.runtimeIDMethods = append(inventory.runtimeIDMethods, key)
	}
	if fn.Type.Params == nil {
		return
	}
	for _, field := range fn.Type.Params.List {
		ident, isString := field.Type.(*ast.Ident)
		if !isString || ident.Name != "string" {
			continue
		}
		for _, name := range field.Names {
			if name.Name != "identityID" {
				continue
			}
			if allowedCompatibilityIdentityParameters[key] {
				inventory.allowedParameters = append(inventory.allowedParameters, key)
			} else {
				inventory.unexpectedParameters = append(inventory.unexpectedParameters, key)
			}
		}
	}
}

func inventoryIdentityFields(path string, decl *ast.GenDecl, inventory *productStoreInventory) {
	if decl.Tok != token.TYPE {
		return
	}
	for _, spec := range decl.Specs {
		typeSpec, ok := spec.(*ast.TypeSpec)
		if !ok {
			continue
		}
		structType, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			continue
		}
		for _, field := range structType.Fields.List {
			for _, name := range field.Names {
				tag := ""
				if field.Tag != nil {
					tag = field.Tag.Value
				}
				if name.Name != "identityID" && name.Name != "IdentityID" && name.Name != "TargetIdentityID" &&
					!strings.Contains(tag, `json:"identity_id`) && !strings.Contains(tag, `json:"target_identity_id`) {
					continue
				}
				key := fmt.Sprintf("%s:%s.%s", path, typeSpec.Name.Name, name.Name)
				if allowedCompatibilityIdentityFields[key] {
					inventory.allowedFields = append(inventory.allowedFields, key)
				} else {
					inventory.unexpectedFields = append(inventory.unexpectedFields, key)
				}
			}
		}
	}
}

func assertExactInventory(t *testing.T, label string, got []string, want map[string]bool) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want exact allowlist %v", label, got, sortedKeys(want))
	}
	for _, entry := range got {
		if !want[entry] {
			t.Fatalf("%s contains unexpected entry %q", label, entry)
		}
	}
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
