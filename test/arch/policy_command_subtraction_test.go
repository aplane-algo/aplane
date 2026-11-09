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

// TestAppolicyShipsWithTheSignerBinaries pins where appolicy is built,
// packaged, installed and removed. It is a signer-side tool: built for every
// platform the signer ships on, installed into the signer bindir by the
// install copy loop (no exclusion), never left in the client bindir, and
// removed with the signer binaries on uninstall.
func TestAppolicyShipsWithTheSignerBinaries(t *testing.T) {
	root := filepath.Join("..", "..")
	read := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}

	installer := read("install.sh")
	if strings.Contains(installer, `[ "$name" = "appolicy" ]`) {
		t.Error("install.sh still skips appolicy in a binary copy loop")
	}
	if strings.Contains(installer, `"$SIGNER_BINDIR/appolicy"`) {
		t.Error("install.sh removes appolicy from the signer bindir")
	}
	if !strings.Contains(installer, `rm -f "$CLIENT_BINDIR/appolicy"`) {
		t.Error("install.sh does not remove a client-side appolicy left by an earlier release")
	}

	removal := regexp.MustCompile(`(?m)^\s*for binary in [^\n]*\bappolicy\b[^\n]*; do\s*$`)
	if got := len(removal.FindAllString(read("uninstall.sh"), -1)); got != 2 {
		t.Errorf("uninstall.sh includes appolicy in %d signer-binary removal lists, want 2", got)
	}

	makefile := read("Makefile")
	for _, want := range []string{
		"-o bin/appolicy ./cmd/appolicy",
		"-o appolicy-arm64 ./cmd/appolicy",
		"@mv appolicy-arm64 bin/arm64/appolicy",
		"-o bin/amd64/appolicy ./cmd/appolicy",
		"-o bin/darwin-arm64/appolicy ./cmd/appolicy",
		"-o bin/darwin-amd64/appolicy ./cmd/appolicy",
		"bin/$${arch}/appolicy",
		"$${darwindir}appolicy",
	} {
		if !strings.Contains(makefile, want) {
			t.Errorf("Makefile lacks %q", want)
		}
	}
	release := read(filepath.Join(".github", "workflows", "release.yml"))
	for _, want := range []string{"bin/${arch}/appolicy", "bin/darwin-${arch}/appolicy"} {
		if !strings.Contains(release, want) {
			t.Errorf("release.yml does not package %q", want)
		}
	}
	if !regexp.MustCompile(`(?m)^\s+appolicy$`).MatchString(read(filepath.Join("scripts", "package-bootstrap-release.sh"))) {
		t.Error("package-bootstrap-release.sh does not require appolicy")
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
		// policyreview owns what the operator reviews before an apply; the
		// batch commands and the TUI's load-policy-file flow are its only users.
		"github.com/aplane-algo/aplane/internal/signerapp/policyreview": {
			filepath.Join("internal", "signerapp", "policycmd"): true,
			filepath.Join("internal", "signerapp", "signertui"): true,
		},
		// policytext holds the text-level helpers for policy documents
		// (comments, templates, presets). It has no store or admin
		// dependencies, so policy authoring can use it without policyreview.
		"github.com/aplane-algo/aplane/internal/signerapp/policytext": {
			filepath.Join("internal", "signerapp", "policyauthor"): true,
			filepath.Join("internal", "signerapp", "policyreview"): true,
			filepath.Join("internal", "signerapp", "policycmd"):    true,
			filepath.Join("internal", "signerapp", "signertui"):    true,
		},
		// policyapply owns the rules for committing policy; the daemon admin
		// service, the rescue workflow, and apstore's checks are its only users.
		"github.com/aplane-algo/aplane/internal/signerapp/policyapply": {
			filepath.Join("cmd", "apstore"):                     true,
			filepath.Join("internal", "signerapp", "admin"):     true,
			filepath.Join("internal", "signerapp", "policycmd"): true,
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
				allowed, cosigned := rules[importPath]
				if cosigned && !allowed[dir] {
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
