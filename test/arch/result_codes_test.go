// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const resultCodesFile = "internal/protocol/error_codes.go"

// TestPolicyAndASAResultCodesComeFromProtocol keeps the policy and ASA set
// result codes in internal/protocol, where producers and clients share them.
// Where the packages that emit them give a code (a result's Code, the code of
// policyapply.Error or asaError, the code or fallback of Code, asaCode and
// resultError), they write no string, and nowhere do they write out a code that
// internal/protocol names.
func TestPolicyAndASAResultCodesComeFromProtocol(t *testing.T) {
	emitters := []string{"internal/signerapp/policyapply/", "internal/signerapp/admin/", "internal/signerapp/policycmd/"}
	named := protocolCodeValues(t)
	codeArgument := map[string]int{"resultError": 0, "Code": 1, "asaCode": 1}

	files, given := 0, 0
	forEachProductionFile(t, func(rel string, parsed *ast.File) {
		inScope := false
		for _, prefix := range emitters {
			inScope = inScope || strings.HasPrefix(rel, prefix)
		}
		if !inScope {
			return
		}
		files++
		requireNoString := func(expr ast.Expr) {
			given++
			ast.Inspect(expr, func(node ast.Node) bool {
				if value, ok := stringLiteral(node); ok && value != "" {
					t.Errorf("%s gives the code %q as a string; name it in %s", rel, value, resultCodesFile)
				}
				return true
			})
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.BasicLit:
				if value, ok := stringLiteral(node); ok && named[value] {
					t.Errorf("%s writes out the code %q; use the constant in %s", rel, value, resultCodesFile)
				}
			case *ast.KeyValueExpr:
				if key, ok := node.Key.(*ast.Ident); ok && (key.Name == "Code" || key.Name == "code") {
					requireNoString(node.Value)
				}
			case *ast.CompositeLit:
				if name := typeName(node.Type); (name == "Error" || name == "asaError") && len(node.Elts) > 0 {
					if _, keyed := node.Elts[0].(*ast.KeyValueExpr); !keyed {
						requireNoString(node.Elts[0])
					}
				}
			case *ast.CallExpr:
				if i, ok := codeArgument[typeName(node.Fun)]; ok && i < len(node.Args) {
					requireNoString(node.Args[i])
				}
			case *ast.AssignStmt:
				for i, left := range node.Lhs {
					if selector, ok := left.(*ast.SelectorExpr); ok && selector.Sel.Name == "Code" && i < len(node.Rhs) {
						requireNoString(node.Rhs[i])
					}
				}
			}
			return true
		})
	})
	if files == 0 || given == 0 {
		t.Fatalf("%d files of the emitting packages give %d codes; the guard no longer sees them", files, given)
	}
}

// protocolCodeValues are the wire values of the codes internal/protocol names.
func protocolCodeValues(t *testing.T) map[string]bool {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", filepath.FromSlash(resultCodesFile)), nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]bool)
	ast.Inspect(parsed, func(node ast.Node) bool {
		if spec, ok := node.(*ast.ValueSpec); ok {
			for _, expr := range spec.Values {
				if value, ok := stringLiteral(expr); ok {
					values[value] = true
				}
			}
		}
		return true
	})
	if len(values) == 0 {
		t.Fatalf("%s names no code", resultCodesFile)
	}
	return values
}

func stringLiteral(node ast.Node) (string, bool) {
	lit, ok := node.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	return value, err == nil
}

// typeName is the last name of a possibly qualified identifier.
func typeName(expr ast.Expr) string {
	switch expr := expr.(type) {
	case *ast.Ident:
		return expr.Name
	case *ast.SelectorExpr:
		return expr.Sel.Name
	}
	return ""
}
