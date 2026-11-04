// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
)

// Structured logging has no format verbs and spreads across lines, so the line
// scan cannot see it: slog.Info("loaded", "key", privateKey) reads as harmless.
// This pass reads the syntax tree instead and applies the same naming rules to
// the arguments of logging calls.
//
// It matches names, as the line scan does. It is not taint tracking: a value
// renamed to something innocent, or a struct holding a secret, is not found.

// logMethods are the methods that log on a *slog.Logger, or that bind attributes
// to every later record. Repository wrappers such as cache.Debug share these
// names. The receiver's type is unknown here, so any selector with these names
// is treated as logging; the argument naming rules keep that from being noisy.
var logMethods = map[string]bool{
	"Debug": true, "Info": true, "Warn": true, "Error": true,
	"DebugContext": true, "InfoContext": true, "WarnContext": true, "ErrorContext": true,
	"Log": true, "LogAttrs": true, "With": true,
}

// logWrappers are the repository's unqualified logging helpers.
var logWrappers = map[string]bool{
	"Debug": true, "infof": true, "warnf": true,
	"logInfof": true, "logWarnf": true, "logErrorf": true,
}

// sizeOnly reports a builtin whose result says nothing about its argument.
func sizeOnly(call *ast.CallExpr) bool {
	ident, ok := call.Fun.(*ast.Ident)
	return ok && (ident.Name == "len" || ident.Name == "cap")
}

// slogImportName returns the name log/slog is imported under in file, or "".
func slogImportName(file *ast.File) string {
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || path != "log/slog" {
			continue
		}
		if spec.Name != nil {
			return spec.Name.Name
		}
		return "slog"
	}
	return ""
}

// isLoggingCall reports whether call logs or builds something that gets logged.
// Every function in log/slog counts, so attributes built apart from the logging
// call are checked where they are made.
func isLoggingCall(call *ast.CallExpr, slogName string) bool {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return logWrappers[fun.Name]
	case *ast.SelectorExpr:
		if pkg, ok := fun.X.(*ast.Ident); ok && slogName != "" && pkg.Name == slogName {
			return true
		}
		return logMethods[fun.Sel.Name]
	}
	return false
}

func sensitiveIdentifier(name string) bool {
	return sensitiveName.MatchString(name) && !namesAboutKeyMaterial(name)
}

// sensitiveNames finds identifiers in expr that name key material, reporting
// each at its own position so a multiline call points at the right line. A
// selector is judged by its last name, as the line scan does: account.PrivateKey
// is sensitive and seed.Length is not. Called function names are not data.
func sensitiveNames(expr ast.Expr, report func(token.Pos, string)) {
	ast.Inspect(expr, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.FuncLit:
			return false
		case *ast.CallExpr:
			if sizeOnly(n) {
				return false
			}
			if fun, ok := n.Fun.(*ast.SelectorExpr); ok {
				sensitiveNames(fun.X, report)
			}
			for _, arg := range n.Args {
				sensitiveNames(arg, report)
			}
			return false
		case *ast.SelectorExpr:
			if sensitiveIdentifier(n.Sel.Name) {
				report(n.Sel.Pos(), n.Sel.Name)
			}
			return false
		case *ast.Ident:
			if sensitiveIdentifier(n.Name) {
				report(n.Pos(), n.Name)
			}
		}
		return true
	})
}

// structuredLogFindings returns the logging-call arguments in src that name key
// material. Nested logging calls are visited once, from the outermost call.
func structuredLogFindings(path string, src []byte) ([]finding, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	lines := strings.Split(string(src), "\n")
	slogName := slogImportName(file)
	var findings []finding
	seen := make(map[int]bool)

	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || !isLoggingCall(call, slogName) {
			return true
		}
		report := func(pos token.Pos, name string) {
			line := fset.Position(pos).Line
			if seen[line] {
				return
			}
			seen[line] = true
			content := ""
			if line <= len(lines) {
				content = lines[line-1]
			}
			findings = append(findings, finding{
				file:    path,
				line:    line,
				content: content,
				reason:  "Potential key material in structured log argument: " + name,
			})
		}
		if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
			sensitiveNames(fun.X, report)
		}
		for _, arg := range call.Args {
			sensitiveNames(arg, report)
		}
		return false
	})
	return findings, nil
}
