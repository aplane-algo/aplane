// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var retiredAppolicyName = regexp.MustCompile(`(?i)(^|[^a-z0-9])appolicy([^a-z0-9]|$)`)

func TestRetiredAppolicyArtifactDoesNotReturn(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "cmd", "appolicy")); !os.IsNotExist(err) {
		t.Fatalf("retired cmd/appolicy exists: %v", err)
	}

	for _, relative := range []string{
		"Makefile",
		"README.md",
		"AGENTS.md",
		filepath.Join("cmd", "apadmin", "README.md"),
		"bootstrap-install.sh",
	} {
		assertFileExcludesRetiredAppolicy(t, root, relative)
	}
	for _, relative := range []string{
		filepath.Join(".github", "workflows"),
		"installer",
		"scripts",
	} {
		assertTreeExcludesRetiredAppolicy(t, root, relative)
	}

	assertDocumentationExcludesRetiredAppolicy(t, root)
	assertProductionSourceExcludesRetiredAppolicy(t, root)
}

func TestRetiredAppolicyIsRemovedDuringUpgradeAndUninstall(t *testing.T) {
	root := filepath.Join("..", "..")
	installer, err := os.ReadFile(filepath.Join(root, "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{`"$CLIENT_BINDIR/appolicy"`, `"$SIGNER_BINDIR/appolicy"`} {
		if !strings.Contains(string(installer), path) {
			t.Errorf("install.sh does not remove retired upgrade artifact %s", path)
		}
	}

	uninstaller, err := os.ReadFile(filepath.Join(root, "uninstall.sh"))
	if err != nil {
		t.Fatal(err)
	}
	retiredRemoval := regexp.MustCompile(`(?m)^\s*for binary in [^\n]*\bappolicy\b[^\n]*; do\s*$`)
	if !retiredRemoval.Match(uninstaller) {
		t.Error("uninstall.sh does not include appolicy in the signer-binary removal list")
	}
}

func TestRetiredAppolicyPassphraseCannotBecomeCredentialSource(t *testing.T) {
	path := filepath.Join("..", "..", "internal", "signerapp", "policycmd")
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		filename := filepath.Join(path, entry.Name())
		parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range retiredCredentialReaders(parsed) {
			t.Errorf("%s:%s reads the retired APPOLICY_PASSPHRASE source", filepath.Base(filename), declaration)
		}
	}
}

func TestRetiredCredentialDetectorCatchesIdentifierAndLiteral(t *testing.T) {
	source := `package policycmd
import "os"
const retiredPassphraseEnv = "APPOLICY_PASSPHRASE"
var packageRead = os.Getenv(retiredPassphraseEnv)
func RejectRetiredEnvironment() { _ = os.Getenv("APPOLICY_PASSPHRASE") }
func identifierRead() { _ = os.Getenv(retiredPassphraseEnv) }
func literalRead() { _ = os.Getenv("APPOLICY_PASSPHRASE") }
`
	parsed, err := parser.ParseFile(token.NewFileSet(), "mutation.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"package declaration": true, "identifierRead": true, "literalRead": true}
	for _, function := range retiredCredentialReaders(parsed) {
		if !want[function] {
			t.Errorf("unexpected retired credential reader %q", function)
		}
		delete(want, function)
	}
	for function := range want {
		t.Errorf("detector missed retired credential reader %q", function)
	}
}

func TestRescuePolicyOutputCannotBypassVerifiedStoreRead(t *testing.T) {
	path := filepath.Join("..", "..", "internal", "signerapp", "policycmd", "rescue.go")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "os.ReadFile(") {
		t.Error("rescue policy workflow reads output bytes outside OfflineStore verification")
	}
}

func retiredCredentialReaders(parsed *ast.File) []string {
	var readers []string
	for _, decl := range parsed.Decls {
		switch decl := decl.(type) {
		case *ast.FuncDecl:
			if decl.Body != nil && decl.Name.Name != "RejectRetiredEnvironment" && containsRetiredCredential(decl.Body) {
				readers = append(readers, decl.Name.Name)
			}
		case *ast.GenDecl:
			for _, spec := range decl.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if ok && definesRetiredCredentialConstant(decl, value) {
					continue
				}
				if containsRetiredCredential(spec) {
					readers = append(readers, "package declaration")
					break
				}
			}
		}
	}
	return readers
}

func containsRetiredCredential(root ast.Node) bool {
	found := false
	ast.Inspect(root, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.Ident:
			found = found || node.Name == "retiredPassphraseEnv"
		case *ast.BasicLit:
			if node.Kind == token.STRING {
				value, err := strconv.Unquote(node.Value)
				found = found || err == nil && value == "APPOLICY_PASSPHRASE"
			}
		}
		return !found
	})
	return found
}

func definesRetiredCredentialConstant(decl *ast.GenDecl, value *ast.ValueSpec) bool {
	if decl.Tok != token.CONST || len(value.Names) != 1 || value.Names[0].Name != "retiredPassphraseEnv" || len(value.Values) != 1 {
		return false
	}
	literal, ok := value.Values[0].(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return false
	}
	decoded, err := strconv.Unquote(literal.Value)
	return err == nil && decoded == "APPOLICY_PASSPHRASE"
}

func TestPolicyWorkflowImportsStayInOwningBoundaries(t *testing.T) {
	root := filepath.Join("..", "..")
	rules := map[string]map[string]bool{
		"github.com/aplane-algo/aplane/internal/signerapp/policycmd": {
			filepath.Join("cmd", "apadmin"): true,
		},
		"github.com/aplane-algo/aplane/internal/signerapp/policytui": {
			filepath.Join("cmd", "apadmin"):                     true,
			filepath.Join("internal", "signerapp", "signertui"): true,
		},
		"github.com/aplane-algo/aplane/internal/signerapp/policyeditor": {
			filepath.Join("cmd", "apadmin"):                     true,
			filepath.Join("internal", "signerapp", "policycmd"): true,
			filepath.Join("internal", "signerapp", "policytui"): true,
			filepath.Join("internal", "signerapp", "signertui"): true,
		},
	}
	for _, sourceRoot := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, sourceRoot), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			dir := filepath.Dir(relative)
			for _, spec := range parsed.Imports {
				importPath, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					return err
				}
				allowed, guarded := rules[importPath]
				if guarded && !allowed[dir] {
					t.Errorf("%s imports %s outside the policy workflow ownership allowlist", relative, importPath)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func assertFileExcludesRetiredAppolicy(t *testing.T, root, relative string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, relative))
	if err != nil {
		t.Fatal(err)
	}
	if retiredAppolicyName.Match(data) {
		t.Errorf("%s still contains the retired appolicy binary or artifact", relative)
	}
}

func assertTreeExcludesRetiredAppolicy(t *testing.T, root, relative string) {
	t.Helper()
	err := filepath.WalkDir(filepath.Join(root, relative), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if retiredAppolicyName.Match(data) {
			relativePath, _ := filepath.Rel(root, path)
			t.Errorf("%s still contains the retired appolicy binary or artifact", relativePath)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assertDocumentationExcludesRetiredAppolicy(t *testing.T, root string) {
	t.Helper()
	userPolicy := filepath.Join(root, "docs", "USER_POLICY.md")
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".md" || path == userPolicy {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if retiredAppolicyName.Match(data) {
			relativePath, _ := filepath.Rel(root, path)
			t.Errorf("%s still documents the retired policy binary", relativePath)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(userPolicy)
	if err != nil {
		t.Fatal(err)
	}
	const migrationStart = "### Migration from the retired policy binary"
	const migrationEnd = "## Top-Level Fields"
	text := string(data)
	start := strings.Index(text, migrationStart)
	end := strings.Index(text, migrationEnd)
	if start < 0 || end <= start {
		t.Fatal("USER_POLICY migration section markers are missing or out of order")
	}
	withoutMigration := text[:start] + text[end:]
	if retiredAppolicyName.MatchString(withoutMigration) {
		t.Error("USER_POLICY documents the retired binary outside its migration section")
	}
}

func assertProductionSourceExcludesRetiredAppolicy(t *testing.T, root string) {
	t.Helper()
	allowedRetirementPath := filepath.Join("internal", "signerapp", "policycmd", "passphrase.go")
	for _, sourceRoot := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, sourceRoot), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if relative == allowedRetirementPath {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if retiredAppolicyName.Match(data) {
				t.Errorf("%s reintroduces the retired appolicy command or workflow", relative)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
