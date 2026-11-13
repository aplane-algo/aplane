// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// These tests hold the contract in "Client Output and Logging" in
// docs/ARCH_SHELL.md: client packages report diagnostics through log/slog, and a
// host decides where they go. They read the syntax of each file, so they catch the
// ordinary ways of getting this wrong, not every way a program can write to a
// terminal.
//
// `make logging-reach-check` holds the other half: that a binary with no handler
// has no reachable way to log.

// scopedOutputPaths are the client source paths where a diagnostic must go through
// slog. Packages end in "/"; a file is listed by itself where only part of a
// package is client code, as with internal/sshtunnel, whose server side belongs to
// the signer. internal/keys is left out on purpose: its scan warning is shared with
// the signer and is outside this contract.
var scopedOutputPaths = []string{
	"internal/apshellapp/",
	"internal/cache/",
	"internal/clientsign/",
	"internal/engine/",
	"internal/plugin/",
	"internal/signerclient/",
	"internal/signing/",
	"internal/sshtunnel/client.go",
	"internal/sshtunnel/identity.go",
	"internal/transport/",
}

// directOutputExceptions are writes the rule allows, keyed by file and then by
// what the file does. Each is a result or progress path, not a diagnostic: the
// caller may pass a writer, and stdout is the fallback when it doesn't. Do not add
// a diagnostic here; log it. An entry that stops matching fails the test, so the
// list shrinks as these writers become required.
var directOutputExceptions = map[string]map[string]string{
	"internal/engine/cosigned/submit.go": {"os.Stdout": "result fallback when the caller passes no writer"},
	"internal/signerclient/client.go":    {"os.Stdout": "progress fallback when the caller sets no ProgressOut"},
	"internal/signing/ed25519.go":        {"os.Stdout": "result fallback when the caller passes no writer"},
	"internal/signing/simulate.go":       {"os.Stdout": "result fallback when the caller passes no writer"},
}

// loggingHosts install a handler. Each must call clientlog.Install in its main
// package before anything can log.
var loggingHosts = []string{"apadmin", "apapprover", "apconsole", "apshell"}

// binariesWithoutHandler link a logging source but have no handler, with the reason
// that is acceptable. `make logging-reach-check` proves the first group can't emit
// a record. The others run their own logging.
var binariesWithoutHandler = map[string]string{
	"aplocalnet":        "logging unreachable; checked by logging-reach-check",
	"appolicy":          "logging unreachable; checked by logging-reach-check",
	"applugin-checksum": "logging unreachable; checked by logging-reach-check",
	"apsigner":          "the signer daemon has its own logging; its SSH client path is unreachable",
}

// loggingSourcePackages are the packages that report through the client pipeline.
var loggingSourcePackages = []string{
	"internal/apshellapp",
	"internal/cache",
	"internal/engine",
	"internal/plugin/discovery",
	"internal/plugin/manager",
	"internal/signerclient",
	"internal/sshtunnel",
	"internal/transport",
}

func inScopedOutputPath(rel string) bool {
	for _, path := range scopedOutputPaths {
		if strings.HasSuffix(path, "/") {
			if strings.HasPrefix(rel, path) {
				return true
			}
		} else if rel == path {
			return true
		}
	}
	return false
}

// importedAs returns the name a package is imported under in file, or "".
func importedAs(file *ast.File, importPath string) string {
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || path != importPath {
			continue
		}
		if spec.Name != nil {
			return spec.Name.Name
		}
		return importPath[strings.LastIndex(importPath, "/")+1:]
	}
	return ""
}

// pkgSelector reports the member name when expr is pkg.Member.
func pkgSelector(expr ast.Expr, pkg string) (string, bool) {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok || pkg == "" {
		return "", false
	}
	ident, ok := selector.X.(*ast.Ident)
	if !ok || ident.Name != pkg {
		return "", false
	}
	return selector.Sel.Name, true
}

// directOutput returns what file does that bypasses the pipeline. fmt.Fprintf to an
// explicit writer is fine; the writer is checked, so os.Stderr as the writer isn't.
func directOutput(file *ast.File) []string {
	fmtName := importedAs(file, "fmt")
	osName := importedAs(file, "os")
	logName := importedAs(file, "log")

	var found []string
	if importedAs(file, "github.com/aplane-algo/aplane/internal/cmdlog") != "" {
		found = append(found, "cmdlog")
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.CallExpr:
			if name, ok := pkgSelector(n.Fun, fmtName); ok && strings.HasPrefix(name, "Print") {
				found = append(found, "fmt."+name)
			}
		case *ast.SelectorExpr:
			if name, ok := pkgSelector(n, osName); ok && (name == "Stdout" || name == "Stderr") {
				found = append(found, "os."+name)
			}
			if name, ok := pkgSelector(n, logName); ok && logName != "" {
				found = append(found, "log."+name)
			}
		}
		return true
	})
	return found
}

// retainedDefaultLogger returns the file's package-level uses of the default
// logger. A logger made during initialization binds the handler of that moment,
// before the host installs one, and bypasses the pipeline. A variable initialized
// from a local function named logger is caught too; other helpers are not.
func retainedDefaultLogger(file *ast.File) []string {
	slogName := importedAs(file, "log/slog")
	var found []string
	inspect := func(node ast.Node) {
		ast.Inspect(node, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if name, ok := pkgSelector(call.Fun, slogName); ok && (name == "With" || name == "Default") {
				found = append(found, "slog."+name)
			}
			if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "logger" {
				found = append(found, "logger()")
			}
			return true
		})
	}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			if d.Tok == token.VAR {
				inspect(d)
			}
		case *ast.FuncDecl:
			if d.Name.Name == "init" && d.Recv == nil {
				inspect(d)
			}
		}
	}
	return found
}

// pipelineBypasses returns ways file reaches a handler other than through ordinary
// logging calls. These skip Logger.log, so the reachability check wouldn't see them.
func pipelineBypasses(file *ast.File) []string {
	slogName := importedAs(file, "log/slog")
	var found []string
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if name, ok := pkgSelector(call.Fun, slogName); ok && name == "NewLogLogger" {
			found = append(found, "slog.NewLogLogger")
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Handler" || len(call.Args) != 0 {
			return true
		}
		// A logger's Handler() has no use here except calling it directly.
		if inner, ok := selector.X.(*ast.CallExpr); ok {
			if name, ok := pkgSelector(inner.Fun, slogName); ok && name == "Default" {
				found = append(found, "slog.Default().Handler()")
			}
		}
		return true
	})
	return found
}

// processLoggingSetup returns calls that change the process's logging.
func processLoggingSetup(file *ast.File) []string {
	slogName := importedAs(file, "log/slog")
	logName := importedAs(file, "log")
	clientlogName := importedAs(file, "github.com/aplane-algo/aplane/internal/clientlog")
	var found []string
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if name, ok := pkgSelector(call.Fun, slogName); ok && (name == "SetDefault" || name == "SetLogLoggerLevel") {
			found = append(found, "slog."+name)
		}
		if name, ok := pkgSelector(call.Fun, logName); ok && name == "SetOutput" {
			found = append(found, "log.SetOutput")
		}
		if name, ok := pkgSelector(call.Fun, clientlogName); ok && name == "Install" {
			found = append(found, "clientlog.Install")
		}
		return true
	})
	return found
}

// forEachProductionGoFile visits every non-test Go file under the given roots.
func forEachProductionGoFile(t *testing.T, root string, dirs []string, visit func(rel string, file *ast.File)) {
	t.Helper()
	fset := token.NewFileSet()
	for _, dir := range dirs {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			visit(filepath.ToSlash(rel), file)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestClientPackagesLogThroughThePipeline(t *testing.T) {
	root := filepath.Join("..", "..")
	used := make(map[string]map[string]bool)
	forEachProductionGoFile(t, root, []string{"internal"}, func(rel string, file *ast.File) {
		if !inScopedOutputPath(rel) {
			return
		}
		for _, use := range directOutput(file) {
			if _, allowed := directOutputExceptions[rel][use]; allowed {
				if used[rel] == nil {
					used[rel] = make(map[string]bool)
				}
				used[rel][use] = true
				continue
			}
			t.Errorf("%s uses %s: report diagnostics through log/slog, or return a result "+
				"(see \"Client Output and Logging\" in docs/ARCH_SHELL.md)", rel, use)
		}
	})
	for rel, uses := range directOutputExceptions {
		for use := range uses {
			if !used[rel][use] {
				t.Errorf("%s no longer uses %s: remove it from directOutputExceptions", rel, use)
			}
		}
	}
}

func TestNoPackageKeepsTheDefaultLogger(t *testing.T) {
	root := filepath.Join("..", "..")
	forEachProductionGoFile(t, root, []string{"cmd", "internal", "lsig", "pkg"}, func(rel string, file *ast.File) {
		for _, use := range retainedDefaultLogger(file) {
			t.Errorf("%s uses %s during package initialization: get the logger at call time, "+
				"or it will miss the handler the host installs", rel, use)
		}
	})
}

func TestOnlyHostsSetUpProcessLogging(t *testing.T) {
	root := filepath.Join("..", "..")
	forEachProductionGoFile(t, root, []string{"cmd", "internal", "lsig", "pkg"}, func(rel string, file *ast.File) {
		if strings.HasPrefix(rel, "cmd/") || strings.HasPrefix(rel, "internal/clientlog/") {
			return
		}
		for _, use := range processLoggingSetup(file) {
			t.Errorf("%s calls %s: only a host's main decides how its process logs", rel, use)
		}
	})
}

func TestNothingBypassesOrdinaryLoggingCalls(t *testing.T) {
	root := filepath.Join("..", "..")
	forEachProductionGoFile(t, root, []string{"cmd", "internal", "lsig", "pkg"}, func(rel string, file *ast.File) {
		if strings.HasPrefix(rel, "internal/clientlog/") {
			return
		}
		for _, use := range pipelineBypasses(file) {
			t.Errorf("%s uses %s, which skips the logging calls logging-reach-check relies on", rel, use)
		}
	})
}

func commandInstallsLogging(t *testing.T, root, binary string) bool {
	t.Helper()
	installed := false
	forEachProductionGoFile(t, root, []string{filepath.Join("cmd", binary)}, func(_ string, file *ast.File) {
		if slices.Contains(processLoggingSetup(file), "clientlog.Install") {
			installed = true
		}
	})
	return installed
}

func TestHostsInstallLogging(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, binary := range loggingHosts {
		if !commandInstallsLogging(t, root, binary) {
			t.Errorf("cmd/%s links logging sources but never calls clientlog.Install", binary)
		}
	}
}

// TestEveryBinaryWithLoggingSourcesIsAccountedFor keeps a new binary from linking a
// logging source without anyone deciding where its records go. A TUI that did would
// have them written across its screen.
func TestEveryBinaryWithLoggingSourcesIsAccountedFor(t *testing.T) {
	root := filepath.Join("..", "..")
	imports := moduleImports(t)
	sources := make(map[string]bool, len(loggingSourcePackages))
	for _, pkg := range loggingSourcePackages {
		sources[modulePrefix+"/"+pkg] = true
	}

	entries, err := os.ReadDir(filepath.Join(root, "cmd"))
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		binary := entry.Name()
		if !linksLoggingSource(imports, modulePrefix+"/cmd/"+binary, sources) {
			continue
		}
		_, exempt := binariesWithoutHandler[binary]
		if !exempt && !slices.Contains(loggingHosts, binary) {
			missing = append(missing, binary)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("binaries link logging sources with no decision about their logs: %v; "+
			"install a handler, or prove it unnecessary in logging-reach-check", missing)
	}
	for binary := range binariesWithoutHandler {
		if !linksLoggingSource(imports, modulePrefix+"/cmd/"+binary, sources) {
			t.Errorf("cmd/%s no longer links a logging source: remove it from binariesWithoutHandler", binary)
		}
	}
}

func linksLoggingSource(imports map[string][]string, start string, sources map[string]bool) bool {
	seen := map[string]bool{start: true}
	queue := []string{start}
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		if sources[pkg] {
			return true
		}
		for _, imp := range imports[pkg] {
			if !seen[imp] {
				seen[imp] = true
				queue = append(queue, imp)
			}
		}
	}
	return false
}

func parseSnippet(t *testing.T, body string) *ast.File {
	t.Helper()
	src := "package sample\n\nimport (\n\t\"fmt\"\n\t\"log\"\n\t\"log/slog\"\n\t\"os\"\n)\n\n" + body + "\n"
	file, err := parser.ParseFile(token.NewFileSet(), "sample.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, src)
	}
	return file
}

// The detectors above decide what this contract enforces, so they are tested
// against what each must reject and what each must leave alone.
func TestLoggingDetectors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		detect func(*ast.File) []string
		body   string
		want   []string
	}{
		{"fmt.Println", directOutput, `func f() { fmt.Println("x") }`, []string{"fmt.Println"}},
		{"fmt.Printf", directOutput, `func f() { fmt.Printf("x") }`, []string{"fmt.Printf"}},
		{"Fprintf to stderr", directOutput, `func f() { fmt.Fprintf(os.Stderr, "x") }`, []string{"os.Stderr"}},
		{"stdout as a value", directOutput, `var w = os.Stdout`, []string{"os.Stdout"}},
		{"standard log", directOutput, `func f() { log.Print("x") }`, []string{"log.Print"}},
		{"Fprintf to a writer is fine", directOutput, `func f(w interface{ Write([]byte) (int, error) }) { fmt.Fprintf(w, "x") }`, nil},
		{"Sprintf is fine", directOutput, `func f() string { return fmt.Sprintf("x") }`, nil},

		{"package var With", retainedDefaultLogger, `var l = slog.With("component", "x")`, []string{"slog.With"}},
		{"package var Default", retainedDefaultLogger, `var l = slog.Default()`, []string{"slog.Default"}},
		{"through a helper", retainedDefaultLogger, `var l = logger()`, []string{"logger()"}},
		{"in init", retainedDefaultLogger, `func init() { l = slog.With("a", 1) }`, []string{"slog.With"}},
		{"at call time is fine", retainedDefaultLogger, `func logger() *slog.Logger { return slog.With("a", 1) }`, nil},

		{"NewLogLogger", pipelineBypasses, `func f(h slog.Handler) { _ = slog.NewLogLogger(h, slog.LevelInfo) }`, []string{"slog.NewLogLogger"}},
		{"direct Handle", pipelineBypasses, `func f(r slog.Record) { _ = slog.Default().Handler().Handle(nil, r) }`, []string{"slog.Default().Handler()"}},
		{"ordinary logging is fine", pipelineBypasses, `func f() { slog.Warn("x") }`, nil},

		{"SetDefault", processLoggingSetup, `func f() { slog.SetDefault(nil) }`, []string{"slog.SetDefault"}},
		{"log.SetOutput", processLoggingSetup, `func f() { log.SetOutput(nil) }`, []string{"log.SetOutput"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.detect(parseSnippet(t, tc.body)); !slices.Equal(got, tc.want) {
				t.Fatalf("found %q, want %q", fmt.Sprint(got), fmt.Sprint(tc.want))
			}
		})
	}
}
