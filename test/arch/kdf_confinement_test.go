// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// keyDerivationPackages are the primitives that turn a passphrase into key
// material. Any one of them outside internal/crypto is a second derivation
// site by definition.
var keyDerivationPackages = map[string]bool{
	"golang.org/x/crypto/argon2": true,
	"golang.org/x/crypto/hkdf":   true,
	"golang.org/x/crypto/pbkdf2": true,
	"golang.org/x/crypto/scrypt": true,
	"golang.org/x/crypto/bcrypt": true,
	"crypto/pbkdf2":              true,
}

// TestKeyDerivationLivesOnlyInCrypto proves the store has exactly one place
// that turns a passphrase into key material.
//
// The compiler already stops code outside internal/crypto from *receiving* a
// raw term key: the compatibility accessors are gone and the raw-key envelope
// functions are unexported. It cannot stop code from deriving its own key with
// Argon2 and wrapping it, which would reintroduce a derivation site with
// different parameters and no keyring behind it. That is what this checks.
//
// Production files are parsed regardless of build tags, so a file behind
// //go:build testmode is covered here even though a plain `go build ./...`
// never sees it.
func TestKeyDerivationLivesOnlyInCrypto(t *testing.T) {
	forEachProductionFile(t, func(rel string, parsed *ast.File) {
		if strings.HasPrefix(rel, "internal/crypto/") {
			return
		}
		for _, spec := range parsed.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				continue
			}
			if keyDerivationPackages[path] {
				t.Errorf(
					"%s imports %s; passphrase derivation belongs to internal/crypto alone",
					rel, path,
				)
			}
		}
	})
}

// TestRawTermKeysAreNotAdoptedOutsideTests proves nothing in production wraps
// bytes it derived itself as a keyring.
//
// NewKeyringFromKey has to stay exported for test fixtures to build a keyring
// from a known key. It is also the one remaining way to place arbitrary bytes
// behind the keyring API, so production use of it would undo the confinement
// the test above enforces.
func TestRawTermKeysAreNotAdoptedOutsideTests(t *testing.T) {
	forEachProductionFile(t, func(rel string, parsed *ast.File) {
		switch {
		case strings.HasPrefix(rel, "internal/crypto/cryptotest/"):
			return // the shared test fixture, used only from _test.go files
		case strings.HasPrefix(rel, "internal/crypto/"):
			return
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "NewKeyringFromKey" {
				return true
			}
			t.Errorf(
				"%s adopts a raw key as a keyring; production code must open a keyring, not construct one",
				rel,
			)
			return true
		})
	})
}

// forEachProductionFile parses every non-test Go file in the repository,
// ignoring build tags so tagged production code is included.
func forEachProductionFile(t *testing.T, visit func(rel string, parsed *ast.File)) {
	t.Helper()
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "temp", "vendor", "node_modules":
				if path != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		visit(rel, parsed)
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}
}
