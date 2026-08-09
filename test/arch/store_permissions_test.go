// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// legacyModeAllowlist is the complete production-code inventory of remaining
// 0770/0660 literals. They are transport/client or migration compatibility,
// never signer-store creation defaults.
var legacyModeAllowlist = map[string]struct{}{
	"internal/clientdata/lock.go":      {},
	"internal/clientstate/watcher.go":  {},
	"internal/fsutil/durable.go":       {},
	"internal/signerapp/daemon/ipc.go": {},
	"internal/storeperm/audit.go":      {},
}

func TestLegacySharedModesStayOutOfSignerStoreWriters(t *testing.T) {
	root := repositoryRoot(t)
	set := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			name := entry.Name()
			if name == ".git" || name == "vendor" || name == "temp" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		file, err := parser.ParseFile(set, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.INT || (literal.Value != "0770" && literal.Value != "0o770" && literal.Value != "0660" && literal.Value != "0o660") {
				return true
			}
			if _, allowed := legacyModeAllowlist[rel]; !allowed {
				t.Errorf("%s:%d uses legacy shared mode %s outside the audited allowlist", rel, set.Position(literal.Pos()).Line, literal.Value)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSystemdUnitsKeepProtectedRuntimeBoundary(t *testing.T) {
	root := repositoryRoot(t)
	for _, rel := range []string{"installer/apsigner.service", "installer/apsigner.service.template"} {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, required := range []string{
			"RuntimeDirectory=apsigner",
			"RuntimeDirectoryMode=0750",
			"UMask=0077",
			"NoNewPrivileges=true",
			"PrivateTmp=true",
		} {
			if !strings.Contains(text, required) {
				t.Errorf("%s is missing %q", rel, required)
			}
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}
