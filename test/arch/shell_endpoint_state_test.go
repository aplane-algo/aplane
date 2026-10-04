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

// TestShellEndpointStateLivesInApshellApp keeps client config and endpoint
// resolution in internal/apshellapp. The shell once held its own config copy
// and resolved aliases from it, so endpoints that the app had already loaded
// stayed unknown to connect and request-token.
func TestShellEndpointStateLivesInApshellApp(t *testing.T) {
	dir := filepath.Join("..", "..", "internal", "apshellcli")
	forbidden := []string{
		"config.LoadConfig(", "ClientEndpointsOrDefault(", ".DefaultEndpoint(",
		"EndpointRegistry", "LoadClientEndpointRegistry(", "LoadStoredClientEndpointRegistry(",
	}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, call := range forbidden {
			if strings.Contains(string(data), call) {
				t.Errorf("%s uses %q; load config and resolve endpoints in internal/apshellapp", path, call)
			}
		}
		file, err := parser.ParseFile(fset, path, data, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			spec, ok := n.(*ast.TypeSpec)
			if !ok || spec.Name.Name != "REPLState" {
				return true
			}
			for _, field := range spec.Type.(*ast.StructType).Fields.List {
				for _, fieldName := range field.Names {
					if fieldName.Name == "Config" {
						t.Errorf("%s: REPLState has a Config field again; read the app's config instead", path)
					}
				}
			}
			return false
		})
	}
}
