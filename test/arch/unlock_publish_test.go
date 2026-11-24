// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"go/ast"
	"strconv"
	"strings"
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
// forwarding, and the lock runtime's EnterRecovery from an unlock's entry
// (unlockIntoRecovery), which installs recovery's view of what the unlock's
// build found.
func TestNoProductionCodeEntersRecoveryOutsideTheFailureRule(t *testing.T) {
	// The functions that may reach the lock runtime's SetRecovery and
	// EnterRecovery, each through ir.lockRuntime.
	allowed := map[string]map[string]map[string]bool{
		"SetRecovery": {
			"internal/signerapp/productruntime/view.go":    {"enterRecoveryViewLocked": true, "reloadViewLocked": true},
			"internal/signerapp/productruntime/runtime.go": {"SetRecovery": true},
		},
		"EnterRecovery": {
			"internal/signerapp/productruntime/view.go": {"unlockIntoRecovery": true},
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

// TestNoProductionCodePublishesWhatNoBuildVerified keeps the product
// runtime's PublishSnapshot and PublishSourceTokens out of production code.
// They put key maps or a source token index in service directly, outside a
// publish of what a build verified (productruntime/view.go publishLocked),
// so a production caller would serve keys or tokens no build checked against
// the generation the root selects. Tests use them to plant a view no store
// could build. Every reference counts, method values included.
func TestNoProductionCodePublishesWhatNoBuildVerified(t *testing.T) {
	seams := map[string]bool{"PublishSnapshot": true, "PublishSourceTokens": true}
	forEachProductionFile(t, func(rel string, parsed *ast.File) {
		ast.Inspect(parsed, func(node ast.Node) bool {
			if selector, ok := node.(*ast.SelectorExpr); ok && seams[selector.Sel.Name] {
				t.Errorf("%s refers to %s, a test seam; a view goes into service through a build's publish",
					rel, selector.Sel.Name)
			}
			return true
		})
	})
}

// TestNoProductionCodeInstallsOrClearsTheKeystoreOutsideItsSeams keeps
// FileKeyStore.Install and ClearKeys confined to the publish, recovery-view,
// and lock/destroy cleanup paths. Every other caller would install a keyring
// or key cache without a build, or drop them outside lock cleanup.
//
// internal/keystore/keystoretest/keystoretest.go is allowed here because
// TestProductionCodeDoesNotImportKeystoreTest keeps that package out of
// production binaries. clientlog.Install is a separate package function and
// is resolved by import path so an alias cannot hide a keystore Install.
func TestNoProductionCodeInstallsOrClearsTheKeystoreOutsideItsSeams(t *testing.T) {
	const clientlogPkg = "github.com/aplane-algo/aplane/internal/clientlog"
	allowed := map[string]map[string]map[string]bool{
		"Install": {
			"internal/keystore/file.go":                 {"ClearKeys": true},
			"internal/signerapp/productruntime/view.go": {"publishLocked": true, "installRecoveryViewLocked": true},
		},
		"ClearKeys": {
			"internal/signerapp/productruntime/runtime.go": {"Destroy": true, "performLockCleanup": true},
		},
	}
	forEachProductionFile(t, func(rel string, parsed *ast.File) {
		if rel == "internal/keystore/keystoretest/keystoretest.go" {
			return
		}
		clientlogNames := map[string]bool{}
		for _, spec := range parsed.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil || path != clientlogPkg {
				continue
			}
			name := path[strings.LastIndex(path, "/")+1:]
			if spec.Name != nil {
				name = spec.Name.Name
			}
			clientlogNames[name] = true
		}
		for _, decl := range parsed.Decls {
			fn, isFunc := decl.(*ast.FuncDecl)
			// Every reference counts, a method value or expression as much as a call.
			ast.Inspect(decl, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				byFile, watched := allowed[selector.Sel.Name]
				if !watched {
					return true
				}
				if selector.Sel.Name == "Install" {
					if ident, ok := selector.X.(*ast.Ident); ok && clientlogNames[ident.Name] {
						return true
					}
				}
				if isFunc && byFile[rel][fn.Name.Name] {
					return true
				}
				owner := "<top-level>"
				if isFunc {
					owner = fn.Name.Name
				}
				t.Errorf("%s: %s refers to %s; keystore contents change only through publish, recovery-view install, or lock/destroy cleanup",
					rel, owner, selector.Sel.Name)
				return true
			})
		}
	})
}
