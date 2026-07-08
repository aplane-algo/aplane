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
// core must not depend on. Pinning this makes ARCH_SPEC Invariant 3 ("Engine
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

// guardedAllowedImports is the pinned dependency surface of the isolated
// guarded (sentry) signing package. The guarded flow is the most
// safety-critical client path, so its imports are kept small and reviewed:
// adding an entry here should be a conscious decision, and the package must
// never import internal/engine (the facade that embeds it).
var guardedAllowedImports = map[string]bool{
	modulePrefix + "/internal/cache":            true,
	modulePrefix + "/internal/clientsign":       true,
	modulePrefix + "/internal/config":           true,
	modulePrefix + "/internal/engine/connect":   true,
	modulePrefix + "/internal/lsig":             true,
	modulePrefix + "/internal/sentry/canonical": true,
	modulePrefix + "/internal/sentry/keytypes":  true,
	modulePrefix + "/internal/signerapi":        true,
	modulePrefix + "/internal/signerclient":     true,
	modulePrefix + "/internal/signing":          true,
	modulePrefix + "/internal/tokenfile":        true,
	modulePrefix + "/internal/txnutil":          true,
}

// TestGuardedPackageStaysIsolated pins the guarded package's dependency
// boundary: it must not import internal/engine (no cycle back into the facade
// that embeds it), and every in-module import must be on the reviewed
// allowlist. This keeps the safety-critical guarded orchestration auditable in
// isolation.
func TestGuardedPackageStaysIsolated(t *testing.T) {
	imports := moduleImports(t)
	imps, ok := imports[modulePrefix+"/internal/engine/guarded"]
	if !ok {
		t.Fatal("internal/engine/guarded not found in module package list")
	}
	for _, imp := range imps {
		if imp == modulePrefix+"/internal/engine" {
			t.Errorf("internal/engine/guarded imports internal/engine: the guarded package must stay isolated from the engine facade that embeds it")
			continue
		}
		if strings.HasPrefix(imp, modulePrefix+"/") && !guardedAllowedImports[imp] {
			t.Errorf("internal/engine/guarded imports %s, which is not on the reviewed guardedAllowedImports allowlist; add it there deliberately if the dependency is intended", imp)
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
