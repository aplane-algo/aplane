// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package arch pins module-wide dependency direction. Per-binary link-set
// guards (e.g. the daemon not compiling its own HTTP client) live next to
// the binary in cmd/apsigner/deps_test.go; this package polices edges that
// span the whole tree.
package arch_test

import (
	"os/exec"
	"strings"
	"testing"
)

const modulePrefix = "github.com/aplane-algo/aplane"

// signerappExceptions are shared packages with a known, tracked dependency on
// internal/signerapp. Do not add entries here to make a build pass; either the
// new package belongs under internal/signerapp, or the type it needs belongs
// in a neutral leaf package.
var signerappExceptions = map[string]string{
	// The signer's own TUI; signer-owned but not yet relocated, pending the
	// god-model split.
	modulePrefix + "/internal/signertui": "signer-owned TUI, relocation deferred",
}

// TestSharedPackagesDoNotImportSignerapp pins the server boundary: packages
// under internal/signerapp are signer-daemon internals, and shared code in
// the internal/ root, lsig/, and pkg/ must not import them. Signer-owned
// packages live under internal/signerapp/ instead (storemut, approvalpolicy,
// policyeditor, policytui moved there for exactly this reason).
func TestSharedPackagesDoNotImportSignerapp(t *testing.T) {
	cmd := exec.Command("go", "list", "-f", `{{.ImportPath}} {{join .Imports " "}}`, "./...")
	cmd.Dir = "../.."
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		pkg := fields[0]
		if !policed(pkg) {
			continue
		}
		if _, ok := signerappExceptions[pkg]; ok {
			continue
		}
		for _, imp := range fields[1:] {
			if strings.HasPrefix(imp, modulePrefix+"/internal/signerapp") {
				t.Errorf("%s imports %s: shared packages must not depend on signer-daemon internals; move the package under internal/signerapp/ or hoist the shared type into a neutral leaf package", pkg, imp)
			}
		}
	}
}

// TestSignerappExceptionsStayCurrent fails when a tracked exception no longer
// imports signerapp, so the allowlist shrinks as the remaining layering work
// lands instead of rotting.
func TestSignerappExceptionsStayCurrent(t *testing.T) {
	cmd := exec.Command("go", "list", "-f", `{{.ImportPath}} {{join .Imports " "}}`, "./...")
	cmd.Dir = "../.."
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}

	stillImports := make(map[string]bool, len(signerappExceptions))
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if _, ok := signerappExceptions[fields[0]]; !ok {
			continue
		}
		for _, imp := range fields[1:] {
			if strings.HasPrefix(imp, modulePrefix+"/internal/signerapp") {
				stillImports[fields[0]] = true
			}
		}
	}
	for pkg := range signerappExceptions {
		if !stillImports[pkg] {
			t.Errorf("%s no longer imports internal/signerapp; remove its exception", pkg)
		}
	}
}

func policed(pkg string) bool {
	switch {
	case strings.HasPrefix(pkg, modulePrefix+"/internal/signerapp"):
		return false
	case strings.HasPrefix(pkg, modulePrefix+"/internal/"),
		strings.HasPrefix(pkg, modulePrefix+"/lsig"),
		strings.HasPrefix(pkg, modulePrefix+"/pkg"):
		return true
	default:
		return false
	}
}
