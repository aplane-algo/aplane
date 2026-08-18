// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestShellResultBoundaryRetiredArtifactsStayDeleted(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "internal", "apshellcli", "render_mcp.go")); !os.IsNotExist(err) {
		t.Fatalf("render_mcp.go returned; MCP projections belong to the shared command result path")
	}

	checks := map[string][]string{
		"internal/apshellcli": {
			"mcpStructured", "mcpFallbackResult", "mcpBlockedCommands", "mcpCaptureHelp",
			"resultFromCommandResult", "type CommandResult interface", "type JSONResult struct",
			"type KeysResult struct", "type ToggleResult struct",
		},
		"internal/plugin": {
			"type Function struct", "type FunctionParam struct", "Functions []Function",
		},
	}
	for rel, forbidden := range checks {
		err := filepath.WalkDir(filepath.Join(root, rel), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, token := range forbidden {
				if strings.Contains(string(data), token) {
					t.Errorf("%s contains retired shell/plugin artifact %q", path, token)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	mcpData, err := os.ReadFile(filepath.Join(root, "internal", "apshellcli", "mcp.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"mcpFallbackResult", "state.SetOutput(&"} {
		if strings.Contains(string(mcpData), forbidden) {
			t.Errorf("mcp.go contains %q; MCP execute must marshal the shared result, not capture terminal output", forbidden)
		}
	}
}

func TestInTreePluginManifestsStayCommandOnlyV2(t *testing.T) {
	paths := []string{
		"plugins/algokit-localnet/manifest.json",
		"examples/external_plugins/echo-plugin/manifest.json",
		"examples/external_plugins/reti/manifest.json",
	}
	for _, rel := range paths {
		data, err := os.ReadFile(filepath.Join("..", "..", rel))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if !strings.Contains(text, `"manifest_format": "2.0"`) {
			t.Errorf("%s does not declare manifest format 2.0", rel)
		}
		if strings.Contains(text, `"functions"`) {
			t.Errorf("%s contains retired typed functions metadata", rel)
		}
	}
}

type shellSourceFunction struct {
	id           string
	pkgPath      string
	receiverType string
	receiverName string
	decl         *ast.FuncDecl
	imports      map[string]string
	position     token.Position
}

// TestRegisteredShellHandlersDoNotReachProcessGlobalStdout follows the direct
// static call shapes used by shell handlers: same-receiver methods, local
// functions, and package-qualified functions. Explicit stderr diagnostics are
// not command presentation and are intentionally outside this invariant.
func TestRegisteredShellHandlersDoNotReachProcessGlobalStdout(t *testing.T) {
	root := filepath.Join("..", "..")
	functions := indexInternalSourceFunctions(t, root)
	handlers := registeredShellHandlers(t, root, functions)

	registryData, err := os.ReadFile(filepath.Join(root, "internal", "apshellcli", "registry.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(registryData), `"config":        command.BlockedAutomation(`) {
		t.Fatal("config.DisplayConfig stdout exception requires config to remain explicitly automation-blocked")
	}

	for _, handler := range handlers {
		seen := make(map[string]bool)
		walkShellCalls(t, functions, handler, handler, nil, seen)
	}
}

func indexInternalSourceFunctions(t *testing.T, root string) map[string]*shellSourceFunction {
	t.Helper()
	functions := make(map[string]*shellSourceFunction)
	fset := token.NewFileSet()
	internalRoot := filepath.Join(root, "internal")
	err := filepath.WalkDir(internalRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		pkgPath := modulePrefix + "/" + filepath.ToSlash(rel)
		imports := make(map[string]string)
		for _, spec := range file.Imports {
			importPath := strings.Trim(spec.Path.Value, `"`)
			name := filepath.Base(importPath)
			if spec.Name != nil {
				name = spec.Name.Name
			}
			imports[name] = importPath
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			receiverType, receiverName := sourceReceiver(fn)
			id := sourceFunctionID(pkgPath, receiverType, fn.Name.Name)
			functions[id] = &shellSourceFunction{
				id: id, pkgPath: pkgPath, receiverType: receiverType,
				receiverName: receiverName, decl: fn, imports: imports,
				position: fset.Position(fn.Pos()),
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return functions
}

func registeredShellHandlers(t *testing.T, root string, functions map[string]*shellSourceFunction) []string {
	t.Helper()
	fset := token.NewFileSet()
	path := filepath.Join(root, "internal", "apshellcli", "registry.go")
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var handlers []string
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		fun, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || fun.Sel.Name != "NewInternalHandler" {
			return true
		}
		handler, ok := call.Args[0].(*ast.SelectorExpr)
		if !ok {
			t.Errorf("%s: NewInternalHandler argument is not a method selector", fset.Position(call.Pos()))
			return true
		}
		id := sourceFunctionID(modulePrefix+"/internal/apshellcli", "REPLState", handler.Sel.Name)
		if functions[id] == nil {
			t.Errorf("%s: registered handler %s is not indexed", fset.Position(handler.Pos()), id)
			return true
		}
		handlers = append(handlers, id)
		return true
	})
	sort.Strings(handlers)
	if len(handlers) != 41 {
		t.Fatalf("registered handler roots = %d, want 41", len(handlers))
	}
	return handlers
}

func walkShellCalls(t *testing.T, functions map[string]*shellSourceFunction, root, current string, chain []string, seen map[string]bool) {
	t.Helper()
	if seen[current] {
		return
	}
	seen[current] = true
	fn := functions[current]
	if fn == nil {
		return
	}
	chain = append(chain, current)

	ast.Inspect(fn.decl.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isProcessGlobalStdoutCall(call, fn.imports) {
			allowed := root == sourceFunctionID(modulePrefix+"/internal/apshellcli", "REPLState", "cmdConfig") &&
				current == sourceFunctionID(modulePrefix+"/internal/config", "", "DisplayConfig")
			if !allowed {
				t.Errorf("registered command reaches process-global stdout at %s via %s",
					fn.position, strings.Join(chain, " -> "))
			}
		}
		if target := resolveStaticShellCall(call, fn); target != "" && functions[target] != nil {
			walkShellCalls(t, functions, root, target, chain, seen)
		}
		return true
	})
}

func resolveStaticShellCall(call *ast.CallExpr, fn *shellSourceFunction) string {
	switch called := call.Fun.(type) {
	case *ast.Ident:
		return sourceFunctionID(fn.pkgPath, "", called.Name)
	case *ast.SelectorExpr:
		ident, ok := called.X.(*ast.Ident)
		if !ok {
			return ""
		}
		if importPath, ok := fn.imports[ident.Name]; ok {
			return sourceFunctionID(importPath, "", called.Sel.Name)
		}
		if ident.Name == fn.receiverName && fn.receiverType != "" {
			return sourceFunctionID(fn.pkgPath, fn.receiverType, called.Sel.Name)
		}
	}
	return ""
}

func isProcessGlobalStdoutCall(call *ast.CallExpr, imports map[string]string) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if pkg, ok := selector.X.(*ast.Ident); ok && imports[pkg.Name] == "fmt" {
		switch selector.Sel.Name {
		case "Print", "Printf", "Println":
			return true
		case "Fprint", "Fprintf", "Fprintln":
			return len(call.Args) > 0 && isOSStdout(call.Args[0], imports)
		}
	}
	return selector.Sel.Name == "Write" && isOSStdout(selector.X, imports)
}

func isOSStdout(expr ast.Expr, imports map[string]string) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Stdout" {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	return ok && imports[pkg.Name] == "os"
}

func sourceReceiver(fn *ast.FuncDecl) (string, string) {
	if fn.Recv == nil || len(fn.Recv.List) != 1 {
		return "", ""
	}
	field := fn.Recv.List[0]
	receiverName := ""
	if len(field.Names) == 1 {
		receiverName = field.Names[0].Name
	}
	switch expr := field.Type.(type) {
	case *ast.Ident:
		return expr.Name, receiverName
	case *ast.StarExpr:
		if ident, ok := expr.X.(*ast.Ident); ok {
			return ident.Name, receiverName
		}
	}
	return "", receiverName
}

func sourceFunctionID(pkgPath, receiverType, name string) string {
	if receiverType == "" {
		return pkgPath + "." + name
	}
	return fmt.Sprintf("%s.(%s).%s", pkgPath, receiverType, name)
}
