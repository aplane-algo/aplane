// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"go/ast"
	"strings"
	"testing"
)

// TestReloadRegistersProvidersThroughItsSeam keeps the reload and unlock path
// from registering LogicSig providers in the process-wide registry directly.
// A reload registers its templates through the registry the runtime hands it
// (templates.ProviderRegistry, from productruntime.Runtime.ProviderRegistry),
// so a registry per identity can replace the process-wide one without
// touching the reload. Compiled providers still register at process start
// (lsig/...), outside this path.
func TestReloadRegistersProvidersThroughItsSeam(t *testing.T) {
	reloadPath := []string{
		"internal/signerapp/templates/",
		"internal/signerapp/startup/",
		"internal/signerapp/productruntime/",
		"internal/keystore/",
	}
	registration := map[string]bool{"Register": true, "RegisterIfAbsent": true, "RegisterBatchIfAbsent": true}
	registries := map[string]bool{"lsigprovider": true, "genericlsig": true, "logicsigdsa": true}
	forEachProductionFile(t, func(rel string, parsed *ast.File) {
		inScope := false
		for _, prefix := range reloadPath {
			inScope = inScope || strings.HasPrefix(rel, prefix)
		}
		if !inScope {
			return
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok || !registration[selector.Sel.Name] {
				return true
			}
			if pkg, ok := selector.X.(*ast.Ident); ok && registries[pkg.Name] {
				t.Errorf("%s calls %s.%s; a reload registers through the registry the runtime hands it", rel, pkg.Name, selector.Sel.Name)
			}
			return true
		})
	})
}
