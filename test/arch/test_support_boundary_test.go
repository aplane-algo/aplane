// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"strings"
	"testing"
)

// internal/avmsim is an interpreter for tests: it models a TEAL subset and takes
// signature verdicts from hooks, so production code must never rely on it.
func TestProductionCodeDoesNotImportTheTestInterpreter(t *testing.T) {
	const interpreter = "github.com/aplane-algo/aplane/internal/avmsim"
	imports := moduleImports(t)
	for pkg := range imports {
		if pkg == interpreter || strings.HasPrefix(pkg, "github.com/aplane-algo/aplane/temp/") {
			continue
		}
		if path := dependencyPath(imports, pkg, interpreter); path != nil {
			t.Errorf("%s reaches the test interpreter: %s", pkg, strings.Join(path, " -> "))
		}
	}
}
