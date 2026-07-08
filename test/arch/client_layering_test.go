// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"os/exec"
	"strings"
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

// TestEngineDoesNotImportUILayer pins the client-side engine boundary: the
// business-logic core (internal/engine and its subpackages) must not import UI
// parsing or formatting packages. Engine inputs are resolved application
// values and its outputs are structured data; rendering and command syntax
// live above it. The check is on direct imports, matching the daemon-side
// layering guards.
func TestEngineDoesNotImportUILayer(t *testing.T) {
	imports := directImports(t)
	for pkg, imps := range imports {
		if !strings.HasPrefix(pkg, modulePrefix+"/internal/engine") {
			continue
		}
		for _, imp := range imps {
			for _, forbidden := range uiLayerPackages {
				if imp == forbidden {
					t.Errorf("%s imports %s: the engine core must not depend on UI parsing/formatting; keep resolved values in and structured results out, and move presentation to the UI layer", pkg, imp)
				}
			}
		}
	}
}

// TestClientStateDoesNotImportUILayer pins the same boundary for the
// cache-backed client state layer. addressdisplay is a deliberate exception:
// clientstate.FormatAddressWithAuth composes the shared address display helper,
// which is the one presentation concern that layer legitimately owns.
func TestClientStateDoesNotImportUILayer(t *testing.T) {
	allowed := map[string]bool{modulePrefix + "/internal/addressdisplay": true}
	imports := directImports(t)
	imps := imports[modulePrefix+"/internal/clientstate"]
	for _, imp := range imps {
		for _, forbidden := range uiLayerPackages {
			if imp == forbidden && !allowed[imp] {
				t.Errorf("internal/clientstate imports %s: cache-backed client state must not depend on UI parsing/formatting", imp)
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
	imports := directImports(t)
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

// directImports returns each module package's direct import list.
func directImports(t *testing.T) map[string][]string {
	t.Helper()
	cmd := exec.Command("go", "list", "-f", `{{.ImportPath}} {{join .Imports " "}}`, "./...")
	cmd.Dir = "../.."
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	result := make(map[string][]string)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		result[fields[0]] = fields[1:]
	}
	return result
}
