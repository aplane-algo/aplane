// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const (
	templateLibraryPackage = modulePrefix + "/internal/templatelibrary"
	templateStorePackage   = modulePrefix + "/internal/templatestore"
	keyTypeStatePackage    = modulePrefix + "/internal/keytypestate"
	templateAdminPackage   = modulePrefix + "/internal/signerapp/templateadmin"
	templateRuntimePackage = modulePrefix + "/internal/signerapp/templates"
	templateRepairPackage  = modulePrefix + "/internal/signerapp/templaterepair"
	apstorePackage         = modulePrefix + "/cmd/apstore"
)

var templateLeafMutationAPIs = map[string]map[string]bool{
	templateStorePackage: {
		"SaveTemplateActive": true,
	},
	keyTypeStatePackage: {
		"Put":          true,
		"PutActive":    true,
		"Delete":       true,
		"DeleteActive": true,
	},
}

// templateLeafCallers confines a mutation API to the templatelibrary
// functions named here. DeleteActive deletes a record from any generation,
// staged or active, without the in-use check a removal applies, so only the
// removal's shared helper and the template repair's drop may call it.
var templateLeafCallers = map[string]map[string]bool{
	keyTypeStatePackage + ".DeleteActive": {
		"removeInstalledActive":    true,
		"DropTemplateRecordActive": true,
	},
}

// templateRepairAPIs are the templatelibrary record repairs. A re-pin
// trusts whatever template authenticates for the key type, and a drop
// deletes a record with no in-use check, each on any generation handle, so
// only the offline repair, which checks both against reload's classification
// first, may call them.
var templateRepairAPIs = map[string]map[string]bool{
	templateLibraryPackage: {
		"RepinTemplateRecordActive": true,
		"DropTemplateRecordActive":  true,
	},
}

var retiredTemplatePersistenceAPIs = map[string]map[string]bool{
	"internal/keytypestate/state.go": {
		"SetState":            true,
		"SetStateActive":      true,
		"ListEnabledActive":   true,
		"RequireUnusedActive": true,
	},
	"internal/templatestore/store.go": {
		"SaveTemplateForPaths": true,
	},
}

type templateLeafCall struct {
	packagePath string
	api         string
	// function is the name of the function declaration the call is in, or
	// "" outside one.
	function string
	position token.Position
}

// TestTemplateMutationCallsStayInLibrary makes templatelibrary the sole
// feature-level caller of the primitive template and key-type mutation APIs.
// Readers may import the persistence packages, but they may not write through
// them directly.
func TestTemplateMutationCallsStayInLibrary(t *testing.T) {
	root := repositoryRoot(t)
	ownerCalls := make(map[string]bool)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "temp":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}

		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		packagePath := modulePrefix + "/" + filepath.ToSlash(filepath.Dir(relative))
		calls, dotImports, err := templateLeafCallsInFile(path, templateLeafMutationAPIs)
		if err != nil {
			return err
		}
		for _, imported := range dotImports {
			if packagePath != templateLibraryPackage {
				t.Errorf("%s dot-imports %s: leaf persistence packages must be referenced explicitly so mutation ownership remains inspectable", filepath.ToSlash(relative), imported)
			}
		}
		for _, call := range calls {
			key := call.packagePath + "." + call.api
			if packagePath == templateLibraryPackage {
				ownerCalls[key] = true
				if callers := templateLeafCallers[key]; callers != nil && !callers[call.function] {
					t.Errorf("%s:%d calls %s from %q: only %v may call it", filepath.ToSlash(relative), call.position.Line, key, call.function, slices.Sorted(maps.Keys(callers)))
				}
				continue
			}
			t.Errorf("%s:%d calls %s: production template/key-type mutation must route through internal/templatelibrary", filepath.ToSlash(relative), call.position.Line, key)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk production Go files: %v", err)
	}

	for packagePath, apis := range templateLeafMutationAPIs {
		for api := range apis {
			key := packagePath + "." + api
			if !ownerCalls[key] {
				t.Errorf("internal/templatelibrary no longer calls %s; remove the unused mutation API or update the boundary deliberately", key)
			}
		}
	}
}

// TestTemplateRecordRepairsStayInTheOfflineRepair confines the record
// repairs to internal/signerapp/templaterepair, and that package to
// apstore, which runs it with the signer stopped.
func TestTemplateRecordRepairsStayInTheOfflineRepair(t *testing.T) {
	root := repositoryRoot(t)
	repairCalls := make(map[string]bool)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "temp":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		packagePath := modulePrefix + "/" + filepath.ToSlash(filepath.Dir(relative))
		calls, dotImports, err := templateLeafCallsInFile(path, templateRepairAPIs)
		if err != nil {
			return err
		}
		for _, imported := range dotImports {
			t.Errorf("%s dot-imports %s: the record repairs must be referenced explicitly so their callers remain inspectable", filepath.ToSlash(relative), imported)
		}
		for _, call := range calls {
			key := call.packagePath + "." + call.api
			if packagePath != templateRepairPackage {
				t.Errorf("%s:%d calls %s: only internal/signerapp/templaterepair may call it", filepath.ToSlash(relative), call.position.Line, key)
				continue
			}
			repairCalls[key] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk production Go files: %v", err)
	}
	for packagePath, apis := range templateRepairAPIs {
		for api := range apis {
			if key := packagePath + "." + api; !repairCalls[key] {
				t.Errorf("internal/signerapp/templaterepair no longer calls %s; remove it or update the boundary deliberately", key)
			}
		}
	}
	for pkg, imports := range moduleImports(t) {
		if pkg != apstorePackage && slices.Contains(imports, templateRepairPackage) {
			t.Errorf("%s imports %s: only cmd/apstore runs the offline template repair", pkg, templateRepairPackage)
		}
	}
}

// TestTemplateMutationDependencyDirection keeps the persistence packages below
// the feature owner, keeps templatelibrary independent of signerapp, and pins
// staged bootstrap to the same feature-level funnel.
func TestTemplateMutationDependencyDirection(t *testing.T) {
	imports := moduleImports(t)
	for _, leaf := range []string{templateStorePackage, keyTypeStatePackage} {
		for _, imported := range imports[leaf] {
			if imported == templateLibraryPackage || imported == templateAdminPackage || imported == templateRuntimePackage {
				t.Errorf("%s imports %s: template persistence leaves must not depend on their feature owner or signer runtime", leaf, imported)
			}
		}
	}
	for _, imported := range imports[templateLibraryPackage] {
		if strings.HasPrefix(imported, modulePrefix+"/internal/signerapp/") {
			t.Errorf("%s imports %s: the template mutation owner must remain independent of signerapp orchestration", templateLibraryPackage, imported)
		}
	}
}

// TestRetiredTemplatePersistenceAPIsStayDeleted prevents the production-unused
// wrappers removed by the boundary cleanup from regrowing around the retained
// primitive APIs.
func TestRetiredTemplatePersistenceAPIsStayDeleted(t *testing.T) {
	root := repositoryRoot(t)
	for relative, retired := range retiredTemplatePersistenceAPIs {
		path := filepath.Join(root, filepath.FromSlash(relative))
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", relative, err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || !retired[function.Name.Name] {
				continue
			}
			t.Errorf("%s reintroduces retired persistence API %s", relative, function.Name.Name)
		}
	}
}

// templateLeafCallsInFile lists the references in path to the apis named,
// keyed by import path, and the import paths of those packages that path
// dot-imports.
func templateLeafCallsInFile(path string, apis map[string]map[string]bool) ([]templateLeafCall, []string, error) {
	fileset := token.NewFileSet()
	file, err := parser.ParseFile(fileset, path, nil, 0)
	if err != nil {
		return nil, nil, err
	}

	aliases := make(map[string]string)
	var dotImports []string
	for _, spec := range file.Imports {
		imported, err := strconv.Unquote(spec.Path.Value)
		if err != nil || apis[imported] == nil {
			continue
		}
		alias := filepath.Base(imported)
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		switch alias {
		case "_":
			continue
		case ".":
			dotImports = append(dotImports, imported)
		default:
			aliases[alias] = imported
		}
	}

	var calls []templateLeafCall
	for _, declaration := range file.Decls {
		function := ""
		if decl, ok := declaration.(*ast.FuncDecl); ok {
			function = decl.Name.Name
		}
		ast.Inspect(declaration, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			packagePath := aliases[ident.Name]
			if packagePath == "" || !apis[packagePath][selector.Sel.Name] {
				return true
			}
			calls = append(calls, templateLeafCall{
				packagePath: packagePath,
				api:         selector.Sel.Name,
				function:    function,
				position:    fileset.Position(selector.Pos()),
			})
			return true
		})
	}
	return calls, dotImports, nil
}

// TestTemplateLeafCallParserResolvesAliases is a fast unit control for the
// import-aware scanner. The repository-level mutation tests exercise the same
// path against real production files.
func TestTemplateLeafCallParserResolvesAliases(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "mutation.go")
	source := `package mutation
import (
  stateleaf "github.com/aplane-algo/aplane/internal/keytypestate"
  storeleaf "github.com/aplane-algo/aplane/internal/templatestore"
)
func mutate() {
  _ = stateleaf.Put
  _ = stateleaf.Delete
  _ = storeleaf.SaveTemplateActive
}
var _ = stateleaf.DeleteActive`
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	calls, dotImports, err := templateLeafCallsInFile(path, templateLeafMutationAPIs)
	if err != nil {
		t.Fatal(err)
	}
	if len(dotImports) != 0 {
		t.Fatalf("dot imports = %v, want none", dotImports)
	}
	want := map[string]string{
		keyTypeStatePackage + ".Put":                 "mutate",
		keyTypeStatePackage + ".Delete":              "mutate",
		templateStorePackage + ".SaveTemplateActive": "mutate",
		keyTypeStatePackage + ".DeleteActive":        "",
	}
	for _, call := range calls {
		key := call.packagePath + "." + call.api
		if function, ok := want[key]; ok && function == call.function {
			delete(want, key)
		}
	}
	if len(want) != 0 {
		t.Fatalf("alias-aware calls missing or in the wrong function: %v", want)
	}
}
