// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"errors"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"testing"
)

// uiLayerPackages are UI/presentation-layer packages that the client engine
// core must not depend on. Pinning this makes ARCH_OVERVIEW Invariant 3 ("Engine
// code is independent of UI parsing/formatting") a checked property rather than
// an asserted one. The list is the parsing/formatting/rendering layer:
// command syntax (cmdspec, shellrepl), the REPL/MCP surface (apshellcli), the
// shell application layer (apshellapp), and terminal presentation (keytypefmt,
// theme, addressdisplay).
var uiLayerPackages = []string{
	modulePrefix + "/internal/cmdspec",
	modulePrefix + "/internal/shellrepl",
	modulePrefix + "/internal/apshellcli",
	modulePrefix + "/internal/apshellapp",
	modulePrefix + "/internal/keytypefmt",
	modulePrefix + "/internal/theme",
	modulePrefix + "/internal/addressdisplay",
}

// TestEngineIsTransitivelyUIFree pins the client-side engine boundary: the
// business-logic core (internal/engine and its subpackages) must not depend on
// UI parsing or formatting packages, directly or through any chain of
// module-internal intermediaries (e.g. engine -> appspec -> appinput must never
// reach cmdspec). Engine inputs are resolved application values and its
// outputs are structured data; rendering and command syntax live above it.
// There are no exceptions: a new UI dependency anywhere in the closure means
// either the helper belongs in a lower semantic package, or the dependency is
// pointed the wrong way.
func TestEngineIsTransitivelyUIFree(t *testing.T) {
	imports := moduleImports(t)

	forbidden := make(map[string]bool, len(uiLayerPackages))
	for _, pkg := range uiLayerPackages {
		forbidden[pkg] = true
	}

	// BFS over module-internal edges from every internal/engine package; a
	// violation is reported at the specific edge that reaches a UI package, so
	// the offending link is named even when the chain is long.
	seen := make(map[string]bool)
	var queue []string
	for pkg := range imports {
		if pkg == modulePrefix+"/internal/engine" || strings.HasPrefix(pkg, modulePrefix+"/internal/engine/") {
			queue = append(queue, pkg)
			seen[pkg] = true
		}
	}
	sort.Strings(queue)
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		for _, imp := range imports[pkg] {
			if !strings.HasPrefix(imp, modulePrefix+"/") {
				continue
			}
			if forbidden[imp] {
				t.Errorf("%s imports %s: the engine core must stay transitively free of UI parsing/formatting; move the needed helper into a semantic leaf package or invert the dependency", pkg, imp)
				continue
			}
			if !seen[imp] {
				seen[imp] = true
				queue = append(queue, imp)
			}
		}
	}
}

// cosignedAllowedImports is the pinned dependency surface of the isolated
// cosigned (cosigner) signing package. The cosigned flow is the most
// safety-critical client path, so its imports are kept small and reviewed:
// adding an entry here should be a conscious decision, and the package must
// never import internal/engine (the facade that embeds it).
var cosignedAllowedImports = map[string]bool{
	modulePrefix + "/internal/cache":              true,
	modulePrefix + "/internal/clientsign":         true,
	modulePrefix + "/internal/config":             true,
	modulePrefix + "/internal/engine/connect":     true,
	modulePrefix + "/internal/lsigresource":       true,
	modulePrefix + "/internal/cosigner/canonical": true,
	modulePrefix + "/internal/signerclient":       true,
	modulePrefix + "/internal/signing":            true,
	modulePrefix + "/internal/txnutil":            true,
	modulePrefix + "/internal/witness":            true,
	modulePrefix + "/pkg/signerapi":               true,
}

// TestCosignedPackageStaysIsolated pins the cosigned package's dependency
// boundary: it must not import internal/engine (no cycle back into the facade
// that embeds it), and every in-module import must be on the reviewed
// allowlist. This keeps the safety-critical cosigned orchestration auditable in
// isolation.
func TestCosignedPackageStaysIsolated(t *testing.T) {
	imports := moduleImports(t)
	imps, ok := imports[modulePrefix+"/internal/engine/cosigned"]
	if !ok {
		t.Fatal("internal/engine/cosigned not found in module package list")
	}
	for _, imp := range imps {
		if imp == modulePrefix+"/internal/engine" {
			t.Errorf("internal/engine/cosigned imports internal/engine: the cosigned package must stay isolated from the engine facade that embeds it")
			continue
		}
		if strings.HasPrefix(imp, modulePrefix+"/") && !cosignedAllowedImports[imp] {
			t.Errorf("internal/engine/cosigned imports %s, which is not on the reviewed cosignedAllowedImports allowlist; add it there deliberately if the dependency is intended", imp)
		}
	}
}

// TestCosignedAllowedImportsStayCurrent fails when an allowlist entry is no
// longer imported by the cosigned package, so the pinned dependency surface
// stays exact instead of accumulating pre-authorized-but-unused entries that
// could be silently re-introduced later without review.
func TestCosignedAllowedImportsStayCurrent(t *testing.T) {
	imports := moduleImports(t)
	current := make(map[string]bool)
	for _, imp := range imports[modulePrefix+"/internal/engine/cosigned"] {
		current[imp] = true
	}
	for allowed := range cosignedAllowedImports {
		if !current[allowed] {
			t.Errorf("internal/engine/cosigned no longer imports %s; remove it from cosignedAllowedImports", allowed)
		}
	}
}

var (
	moduleImportsOnce sync.Once
	moduleImportsMap  map[string][]string
	moduleImportsErr  error
)

// moduleImports returns each module package's direct import list. The
// underlying `go list ./...` walk is run once per test binary and shared by
// every arch test; on failure the go tool's stderr is included so a broken
// package is diagnosable from the test output.
func moduleImports(t *testing.T) map[string][]string {
	t.Helper()
	moduleImportsOnce.Do(func() {
		cmd := exec.Command("go", "list", "-f", `{{.ImportPath}} {{join .Imports " "}}`, "./...")
		cmd.Dir = "../.."
		out, err := cmd.Output()
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
				moduleImportsErr = errors.New(err.Error() + "\n" + string(exitErr.Stderr))
			} else {
				moduleImportsErr = err
			}
			return
		}
		result := make(map[string][]string)
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			result[fields[0]] = fields[1:]
		}
		moduleImportsMap = result
	})
	if moduleImportsErr != nil {
		t.Fatalf("go list: %v", moduleImportsErr)
	}
	return moduleImportsMap
}

// dependencyPath returns the first import chain from root to any of targets
// found by a breadth-first walk of imports, or nil when none is reachable.
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
