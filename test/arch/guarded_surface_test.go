// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// guardedSanctionedExports is the reviewed public API of the isolated guarded
// (sentry) signing package: construction, the two routing/submission entry
// points, endpoint discovery, and the discovery types and error sentinels.
// Everything else in the package is choreography internals that must stay
// unexported so callers cannot compose mid-flow steps out of sequence and skip
// SignAndSubmitGroup's frozen-bytes verification. Adding an entry here must be
// a conscious API decision, mirrored in ARCH_SPEC's guarded ownership entry.
var guardedSanctionedExports = map[string]bool{
	"New":                                true,
	"Deps":                               true,
	"Signer":                             true,
	"SignerCacheView":                    true,
	"DiscoveredSentryComponentKey":       true,
	"ErrSentryDiscoveryInvalidMetadata":  true,
	"ErrSentryDiscoveryUnavailable":      true,
	"ErrSentryDiscoveryLocked":           true,
	"ErrSentryDiscoveryAuth":             true,
	"ErrSentryDiscoveryConfig":           true,
	"Signer.HasGuardedEffectiveSigner":   true,
	"Signer.SignAndSubmitGroup":          true,
	"Signer.DiscoverSentryComponentKeys": true,
}

// TestGuardedExportSurfaceStaysSanctioned pins the guarded package's exported
// identifier set in both directions: an unlisted export fails (a choreography
// internal leaked back out), and a listed-but-missing export fails (the list
// rotted). This makes ARCH_SPEC's "exported surface is only the sanctioned
// entry points" a checked property.
func TestGuardedExportSurfaceStaysSanctioned(t *testing.T) {
	const dir = "../../internal/engine/guarded"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read internal/engine/guarded: %v", err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, file)
	}
	if len(files) == 0 {
		t.Fatal("no production Go files found in internal/engine/guarded")
	}

	found := map[string]bool{}
	for _, file := range files {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if !d.Name.IsExported() {
					continue
				}
				if d.Recv == nil {
					found[d.Name.Name] = true
					continue
				}
				recv := receiverTypeName(d.Recv)
				if recv == "" || !ast.IsExported(recv) {
					continue
				}
				found[recv+"."+d.Name.Name] = true
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch sp := spec.(type) {
					case *ast.TypeSpec:
						if sp.Name.IsExported() {
							found[sp.Name.Name] = true
						}
					case *ast.ValueSpec:
						for _, name := range sp.Names {
							if name.IsExported() {
								found[name.Name] = true
							}
						}
					}
				}
			}
		}
	}

	var unsanctioned, missing []string
	for name := range found {
		if !guardedSanctionedExports[name] {
			unsanctioned = append(unsanctioned, name)
		}
	}
	for name := range guardedSanctionedExports {
		if !found[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(unsanctioned)
	sort.Strings(missing)
	for _, name := range unsanctioned {
		t.Errorf("internal/engine/guarded exports %s, which is not on the sanctioned API list; keep choreography internals unexported, or add it here and to ARCH_SPEC deliberately", name)
	}
	for _, name := range missing {
		t.Errorf("sanctioned export %s no longer exists in internal/engine/guarded; remove it from guardedSanctionedExports and ARCH_SPEC", name)
	}
}

func receiverTypeName(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) == 0 {
		return ""
	}
	expr := recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}
