// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"go/ast"
	"strconv"
	"strings"
	"testing"
)

// assertNoProductionImport fails if any non-test Go file outside ownDirPrefix
// imports banned. It walks the source tree with forEachProductionFile rather
// than go list so build-tagged files (such as testmode or platform-specific
// files) are checked on every host. With no direct importer there can be no
// indirect one.
func assertNoProductionImport(t *testing.T, banned, ownDirPrefix string) {
	t.Helper()
	forEachProductionFile(t, func(rel string, parsed *ast.File) {
		if strings.HasPrefix(rel, ownDirPrefix) {
			return
		}
		for _, spec := range parsed.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				continue
			}
			if path == banned {
				t.Errorf("%s imports %s", rel, banned)
			}
		}
	})
}

// internal/avmsim is an interpreter for tests: it models a TEAL subset and takes
// signature verdicts from hooks, so production code must never rely on it.
func TestProductionCodeDoesNotImportTheTestInterpreter(t *testing.T) {
	assertNoProductionImport(t, "github.com/aplane-algo/aplane/internal/avmsim", "internal/avmsim/")
}

// internal/keystore/keystoretest holds test-only unlock and rescan helpers
// that call FileKeyStore.Install outside a reload's build and publish, so
// production code must never rely on it.
func TestProductionCodeDoesNotImportKeystoreTest(t *testing.T) {
	assertNoProductionImport(t, "github.com/aplane-algo/aplane/internal/keystore/keystoretest", "internal/keystore/keystoretest/")
}
