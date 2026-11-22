// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"go/ast"
	"testing"
)

// TestNoProductionCodePublishesUnlockedWithoutTheFence keeps SetUnlocked out
// of production code. It marks the signer unlocked without the fence an
// unlock attempt passes, which a lock that lands during the attempt's load
// relies on: an unlock request publishes through productruntime.Unlock, and
// a reconcile leaves recovery through PromoteRecoveryToUnlocked. The startup
// unlock once published with it. Tests use it to set up an unlocked runtime.
//
// The one call allowed is the product runtime's SetUnlocked forwarding to
// the lock runtime's.
func TestNoProductionCodePublishesUnlockedWithoutTheFence(t *testing.T) {
	forEachProductionFile(t, func(rel string, parsed *ast.File) {
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if fn.Name.Name == "SetUnlocked" && rel == "internal/signerapp/productruntime/runtime.go" {
				continue
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "SetUnlocked" {
					t.Errorf("%s: %s calls SetUnlocked; an unlock publishes through productruntime.Unlock's fence", rel, fn.Name.Name)
				}
				return true
			})
		}
	})
}
