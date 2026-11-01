// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"sort"
	"strings"
	"testing"
)

// appolicyPackagePrefixes are the packages introduced for appolicy, the
// files-only policy editor: its command and its core, with any subpackage
// either gains (presentation, adapters).
var appolicyPackagePrefixes = []string{
	modulePrefix + "/cmd/appolicy",
	modulePrefix + "/internal/signerapp/policyauthor",
}

// appolicyForbiddenDirect are packages appolicy's own packages must not
// import: the keystore, the store and its mutation, the passphrase and store
// lifecycle, the crypto keyring, and the admin protocol and transport.
var appolicyForbiddenDirect = []string{
	modulePrefix + "/internal/keystore",
	modulePrefix + "/internal/keys",
	modulePrefix + "/internal/genstore",
	modulePrefix + "/internal/signerapp/storemut",
	modulePrefix + "/internal/storeinit",
	modulePrefix + "/internal/storelock",
	modulePrefix + "/internal/storepass",
	modulePrefix + "/internal/crypto",
	modulePrefix + "/internal/adminproto",
	modulePrefix + "/internal/adminipc",
	modulePrefix + "/internal/transport",
	modulePrefix + "/internal/protocol",
	modulePrefix + "/internal/signerapp/policyapply",
	modulePrefix + "/internal/signerapp/policyreview",
}

// appolicyForbiddenTransitive are packages appolicy must not reach by any
// chain of imports: the generation store and the admin protocol and
// transport. (A blanket ban on internal/crypto cannot hold: internal/policy
// imports it for its store sidecars.)
var appolicyForbiddenTransitive = []string{
	modulePrefix + "/internal/genstore",
	modulePrefix + "/internal/adminproto",
	modulePrefix + "/internal/adminipc",
	modulePrefix + "/internal/transport",
}

// TestAppolicyStaysOffTheStoreAndAdminProtocol is a layering constraint on
// appolicy, not proof that it cannot touch a store: shared packages it uses
// still expose store operations. The cmd/appolicy tests back it with checks
// that check, fmt and explain change nothing outside the files they name.
func TestAppolicyStaysOffTheStoreAndAdminProtocol(t *testing.T) {
	imports := moduleImports(t)
	var own []string
	for pkg := range imports {
		for _, prefix := range appolicyPackagePrefixes {
			if pkg == prefix || strings.HasPrefix(pkg, prefix+"/") {
				own = append(own, pkg)
			}
		}
	}
	sort.Strings(own)
	if len(own) < len(appolicyPackagePrefixes) {
		t.Fatalf("found %v, want every package in %v", own, appolicyPackagePrefixes)
	}
	forbidden := map[string]bool{}
	for _, pkg := range appolicyForbiddenDirect {
		forbidden[pkg] = true
	}
	for _, pkg := range own {
		for _, imp := range imports[pkg] {
			if forbidden[imp] {
				t.Errorf("%s imports %s; appolicy works on policy files only", pkg, imp)
			}
		}
		if path := dependencyPath(imports, pkg, appolicyForbiddenTransitive...); path != nil {
			t.Errorf("%s reaches %s", pkg, strings.Join(path, " -> "))
		}
	}
}
