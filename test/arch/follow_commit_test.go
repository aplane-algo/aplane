// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"go/ast"
	"strings"
	"testing"
)

// TestOnlyFollowCommitReloadsAfterAStoreRootCommit keeps the sequence after
// a store-root commit in one place. A commit's caller hands what Mint left
// the root selecting to productruntime.Runtime.FollowCommit, which enters
// recovery before or after its reload as the outcome needs; four callers
// once each wrote that sequence themselves, with their own read-back of the
// root. The commit callers (policy apply, the ASA set, restore, rollback)
// call neither Reload nor SetRecovery for a commit.
//
// The one Reload left is a restore that found nothing new to commit while
// the signer was in recovery: it reloads the current generation, which no
// commit changed.
func TestOnlyFollowCommitReloadsAfterAStoreRootCommit(t *testing.T) {
	commitCallers := []string{"internal/signerapp/admin/", "internal/signerapp/backupadmin/"}
	reloads := map[string]int{}
	forEachProductionFile(t, func(rel string, parsed *ast.File) {
		inScope := false
		for _, prefix := range commitCallers {
			inScope = inScope || strings.HasPrefix(rel, prefix)
		}
		if !inScope {
			return
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Reload" {
				reloads[rel]++
			}
			return true
		})
	})
	want := map[string]int{"internal/signerapp/backupadmin/direct_restore.go": 1}
	for rel, n := range reloads {
		if n != want[rel] {
			t.Errorf("%s calls Reload %d time(s), want %d: a commit's caller follows it with FollowCommit", rel, n, want[rel])
		}
	}
	for rel, n := range want {
		if reloads[rel] != n {
			t.Errorf("%s calls Reload %d time(s), want %d", rel, reloads[rel], n)
		}
	}
}
