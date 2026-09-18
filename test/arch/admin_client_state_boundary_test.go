// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestAdminDoesNotDependOnTransactionClientState(t *testing.T) {
	for _, dir := range []string{"cmd/apadmin", "internal/apadminapp", "internal/signerapp/signertui"} {
		err := filepath.WalkDir(filepath.Join(repositoryRoot(t), dir), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imp := range file.Imports {
				name, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					return err
				}
				for _, forbidden := range []string{"engine", "apshellapp", "clientenroll", "clientdata", "clientstate", "addressbook", "cache", "sshtunnel"} {
					prefix := "github.com/aplane-algo/aplane/internal/" + forbidden
					if name == prefix || strings.HasPrefix(name, prefix+"/") {
						t.Errorf("%s imports client dependency %s", path, name)
					}
				}
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(data), "APCLIENT_DATA") {
				t.Errorf("%s refers to transaction-client data", path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
