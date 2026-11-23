// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"go/ast"
	"strconv"
	"strings"
	"testing"
)

// TestTheRuntimeReachesTheProviderRegistryThroughItsSeam keeps the reload,
// the unlock and template administration off the process-wide LogicSig
// provider registry. They register, look up and unregister templates through
// the registry the runtime hands them (templates.ProviderRegistry, from
// productruntime.Runtime.ProviderRegistry), so a registry per identity can
// replace the process-wide one without touching them. The one reference
// allowed is the runtime's construction of that handle. Compiled providers
// still register at process start (lsig/...), and the key scan's
// signature-size lookups (internal/keys) still read the process-wide
// registry; both are outside this scope.
//
// Imports are resolved by path, so an alias does not hide a call.
func TestTheRuntimeReachesTheProviderRegistryThroughItsSeam(t *testing.T) {
	scope := []string{
		"internal/signerapp/templates/",
		"internal/signerapp/templateadmin/",
		"internal/signerapp/startup/",
		"internal/signerapp/productruntime/",
		"internal/keystore/",
	}
	registries := map[string]bool{
		"github.com/aplane-algo/aplane/internal/lsigprovider": true,
		"github.com/aplane-algo/aplane/internal/genericlsig":  true,
		"github.com/aplane-algo/aplane/internal/logicsigdsa":  true,
	}
	reaches := map[string]bool{
		"Register": true, "RegisterIfAbsent": true, "Unregister": true, "Get": true, "ProcessRegistry": true,
	}
	forEachProductionFile(t, func(rel string, parsed *ast.File) {
		inScope := false
		for _, prefix := range scope {
			inScope = inScope || strings.HasPrefix(rel, prefix)
		}
		if !inScope {
			return
		}
		names := map[string]bool{}
		for _, spec := range parsed.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil || !registries[path] {
				continue
			}
			name := path[strings.LastIndex(path, "/")+1:]
			if spec.Name != nil {
				name = spec.Name.Name
			}
			names[name] = true
		}
		if len(names) == 0 {
			return
		}
		for _, decl := range parsed.Decls {
			fn, isFunc := decl.(*ast.FuncDecl)
			ast.Inspect(decl, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok || !reaches[selector.Sel.Name] {
					return true
				}
				pkg, ok := selector.X.(*ast.Ident)
				if !ok || !names[pkg.Name] {
					return true
				}
				if isFunc && fn.Recv == nil && fn.Name.Name == "New" && selector.Sel.Name == "ProcessRegistry" &&
					rel == "internal/signerapp/productruntime/runtime.go" {
					return true
				}
				t.Errorf("%s uses %s.%s; the runtime reaches the provider registry through the handle it is given", rel, pkg.Name, selector.Sel.Name)
				return true
			})
		}
	})
}
