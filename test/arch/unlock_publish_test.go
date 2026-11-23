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

// TestNoProductionCodeEntersRecoveryOutsideTheFailureRule keeps the test-only
// recovery entries out of production code. Every entry into recovery outside
// an unlock comes from a reload's failure rule (productruntime/view.go),
// which publishes recovery's view of what the build found. Tests set up a
// signer in recovery with productruntime.Runtime.EnterRecovery, which
// publishes recovery's view of the view in service, and land a recovery
// inside an unlock's held load with productruntime.Runtime.SetRecovery,
// which moves the state alone; production can do neither.
//
// The calls allowed are the lock runtime's SetRecovery from the failure
// rule's entries (a reload's, and one for a store in doubt, which enters
// before it builds and installs the view after), the test seams'
// forwarding, and the lock runtime's EnterRecovery from an unlock's entry.
func TestNoProductionCodeEntersRecoveryOutsideTheFailureRule(t *testing.T) {
	// The functions that may reach the lock runtime's SetRecovery and
	// EnterRecovery, each through ir.lockRuntime.
	allowed := map[string]map[string]map[string]bool{
		"SetRecovery": {
			"internal/signerapp/productruntime/view.go":    {"enterRecoveryViewLocked": true, "reloadViewLocked": true},
			"internal/signerapp/productruntime/runtime.go": {"SetRecovery": true},
		},
		"EnterRecovery": {
			"internal/signerapp/productruntime/runtime.go": {"enterRecovery": true},
		},
	}
	forEachProductionFile(t, func(rel string, parsed *ast.File) {
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			// Every reference counts, a method value as much as a call.
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				byFile, watched := allowed[selector.Sel.Name]
				if !watched {
					return true
				}
				onLockRuntime := false
				if inner, ok := selector.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "lockRuntime" {
					onLockRuntime = true
				}
				if !onLockRuntime || !byFile[rel][fn.Name.Name] {
					t.Errorf("%s: %s refers to %s; an entry into recovery outside an unlock comes from a reload's failure rule", rel, fn.Name.Name, selector.Sel.Name)
				}
				return true
			})
		}
	})
}
