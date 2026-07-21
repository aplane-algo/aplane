// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"strings"
	"testing"
)

const (
	helperSignPackage = modulePrefix + "/internal/boundedadmin/helpersign"
	artifactPackage   = modulePrefix + "/internal/witness/artifact"
)

// TestNetworkedAndStoreProcessesCannotReachColdWitnessSigning pins the cold
// custody boundary transitively. These package roots may construct an admin
// transcript, but must never load a standalone witness credential or reach the
// implementation that produces an admin-domain signature.
func TestNetworkedAndStoreProcessesCannotReachColdWitnessSigning(t *testing.T) {
	imports := moduleImports(t)
	for pkg := range imports {
		if !isColdWitnessForbiddenRoot(pkg) {
			continue
		}
		if path := dependencyPath(imports, pkg, helperSignPackage, artifactPackage); len(path) > 0 {
			t.Errorf("cold witness capability reachable from %s: %s", pkg, strings.Join(path, " -> "))
		}
	}
}

func isColdWitnessForbiddenRoot(pkg string) bool {
	return pkg == modulePrefix+"/cmd/apstore" ||
		pkg == modulePrefix+"/internal/keys" || strings.HasPrefix(pkg, modulePrefix+"/internal/keys/") ||
		pkg == modulePrefix+"/internal/keystore" || strings.HasPrefix(pkg, modulePrefix+"/internal/keystore/") ||
		pkg == modulePrefix+"/internal/signerapp" || strings.HasPrefix(pkg, modulePrefix+"/internal/signerapp/")
}

func dependencyPath(imports map[string][]string, root string, targets ...string) []string {
	target := make(map[string]bool, len(targets))
	for _, pkg := range targets {
		target[pkg] = true
	}
	type state struct {
		pkg  string
		path []string
	}
	queue := []state{{pkg: root, path: []string{root}}}
	seen := map[string]bool{root: true}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, imported := range imports[current.pkg] {
			if target[imported] {
				return append(current.path, imported)
			}
			if !strings.HasPrefix(imported, modulePrefix+"/") || seen[imported] {
				continue
			}
			seen[imported] = true
			queue = append(queue, state{pkg: imported, path: append(append([]string(nil), current.path...), imported)})
		}
	}
	return nil
}
