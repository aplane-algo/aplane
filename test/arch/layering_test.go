// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package arch pins module-wide dependency direction. Per-binary link-set
// guards (e.g. the daemon not compiling its own HTTP client) live next to
// the binary in cmd/apsigner/deps_test.go; this package polices edges that
// span the whole tree.
package arch_test

import (
	"strings"
	"testing"
)

const modulePrefix = "github.com/aplane-algo/aplane"

// signerappExceptions are shared packages with a known, tracked dependency on
// internal/signerapp. Do not add entries here to make a build pass; either the
// new package belongs under internal/signerapp, or the type it needs belongs
// in a neutral leaf package.
var signerappExceptions = map[string]string{}

// TestSharedPackagesDoNotImportSignerapp pins the server boundary: packages
// under internal/signerapp are signer-daemon internals, and shared code in
// the internal/ root, lsig/, and pkg/ must not import them. Signer-owned
// packages live under internal/signerapp/ instead (storemut, approvalpolicy,
// policyeditor, policytui, and signertui moved there for exactly this reason).
func TestSharedPackagesDoNotImportSignerapp(t *testing.T) {
	imports := moduleImports(t)

	for pkg, imps := range imports {
		if !policed(pkg) {
			continue
		}
		if _, ok := signerappExceptions[pkg]; ok {
			continue
		}
		for _, imp := range imps {
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
	imports := moduleImports(t)

	stillImports := make(map[string]bool, len(signerappExceptions))
	for pkg, imps := range imports {
		if _, ok := signerappExceptions[pkg]; !ok {
			continue
		}
		for _, imp := range imps {
			if strings.HasPrefix(imp, modulePrefix+"/internal/signerapp") {
				stillImports[pkg] = true
			}
		}
	}
	for pkg := range signerappExceptions {
		if !stillImports[pkg] {
			t.Errorf("%s no longer imports internal/signerapp; remove its exception", pkg)
		}
	}
}

// templateInfraPackages are lsig packages that are template infrastructure
// rather than concrete DSA families; shared code may import them.
var templateInfraPackages = map[string]bool{
	modulePrefix + "/lsig/generictemplate": true,
	modulePrefix + "/lsig/composeddsa":     true,
}

// familyImportExceptions are shared packages with a known, tracked dependency
// on a concrete DSA-family package. Do not add entries to make a build pass;
// family-specific behavior belongs in the family's lsig tree, registered
// through the core registries.
var familyImportExceptions = map[string]string{
	// The guarded component sign/assemble flow is Falcon-only by design until
	// family-neutral component ops exist.
	modulePrefix + "/internal/signerapp/signing": "guarded component flow is falcon-only pending neutral component ops",
}

// TestSharedPackagesDoNotImportDSAFamilies pins the algorithm-family boundary:
// core code under internal/ and pkg/ must stay family-agnostic. Concrete
// family packages (lsig/falcon1024*, lsig/ecdsak1, ...) hook into core through
// registries (keygen, mnemonic, lsigprovider, component-pair validators), so
// the production edge points strictly lsig -> internal. Template
// infrastructure (generictemplate, composeddsa) is exempt; spec-frozen size
// literals with test-only cross-checks are the sanctioned pattern for
// vocabulary packages (see internal/sentry/keytypes).
func TestSharedPackagesDoNotImportDSAFamilies(t *testing.T) {
	imports := moduleImports(t)

	for pkg, imps := range imports {
		if !strings.HasPrefix(pkg, modulePrefix+"/internal/") && !strings.HasPrefix(pkg, modulePrefix+"/pkg") {
			continue
		}
		if _, ok := familyImportExceptions[pkg]; ok {
			continue
		}
		for _, imp := range imps {
			if strings.HasPrefix(imp, modulePrefix+"/lsig/") && !templateInfraPackages[imp] {
				t.Errorf("%s imports %s: core packages must stay algorithm-family-agnostic; register family behavior through the core registries instead", pkg, imp)
			}
		}
	}
}

// TestFamilyImportExceptionsStayCurrent fails when a tracked concrete-family
// import disappears, so the allowlist shrinks as family-neutral registries land.
func TestFamilyImportExceptionsStayCurrent(t *testing.T) {
	imports := moduleImports(t)

	stillImports := make(map[string]bool, len(familyImportExceptions))
	for pkg, imps := range imports {
		if _, ok := familyImportExceptions[pkg]; !ok {
			continue
		}
		for _, imp := range imps {
			if strings.HasPrefix(imp, modulePrefix+"/lsig/") && !templateInfraPackages[imp] {
				stillImports[pkg] = true
			}
		}
	}
	for pkg := range familyImportExceptions {
		if !stillImports[pkg] {
			t.Errorf("%s no longer imports concrete DSA-family packages; remove its exception", pkg)
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
