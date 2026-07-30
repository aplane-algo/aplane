// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// keyDerivationPrimitives are the last path elements of packages that turn a
// passphrase into key material. Any one of them outside internal/crypto is a
// second derivation site by definition.
//
// The match is on the primitive's name rather than a fixed list of import
// paths, because the same primitive ships from several places: hkdf and
// pbkdf2 exist in both golang.org/x/crypto and, since Go 1.24, the standard
// library. An enumerated denylist has to be updated every time one moves, and
// silently passes until someone notices — which is exactly how crypto/hkdf was
// missed here the first time.
var keyDerivationPrimitives = map[string]bool{
	"argon2": true,
	"hkdf":   true,
	"pbkdf2": true,
	"scrypt": true,
	"bcrypt": true,
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
			if keyDerivationPrimitives[pathpkg.Base(path)] {
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
// NewKeyringFromKey, NewKeyringFromTermKey, and NewKeyringFromTermKeys have to
// stay exported for test fixtures to build keyrings from known keys. They are
// also the remaining ways to place arbitrary bytes behind the keyring API, so
// production use would undo the confinement the test above enforces.
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
			if !ok ||
				(selector.Sel.Name != "NewKeyringFromKey" &&
					selector.Sel.Name != "NewKeyringFromTermKey" &&
					selector.Sel.Name != "NewKeyringFromTermKeys") {
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

// TestTestFixturesStayOutOfProduction proves the keyring test fixture is not
// reachable from a shipped binary.
//
// cryptotest exists to build a keyring from known bytes, which is exactly the
// capability production must not have. An import from a non-test file would
// route around both gates above without tripping either.
func TestTestFixturesStayOutOfProduction(t *testing.T) {
	forEachProductionFile(t, func(rel string, parsed *ast.File) {
		for _, spec := range parsed.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err == nil && strings.HasSuffix(path, "/internal/crypto/cryptotest") {
				t.Errorf("%s imports the cryptotest fixture; it is for tests only", rel)
			}
		}
	})
}

// TestHistoricalTermPrimitivesStayBehindGenerationAnchors keeps direct
// retired-term verification and opening confined to genstore. Those exported
// crypto methods exist only to cross the package boundary; callers must use
// genstore's APIs so the exact root anchor, seal, manifest, and member entry
// are checked first.
func TestHistoricalTermPrimitivesStayBehindGenerationAnchors(t *testing.T) {
	forEachProductionFile(t, func(rel string, parsed *ast.File) {
		if strings.HasPrefix(rel, "internal/crypto/") ||
			strings.HasPrefix(rel, "internal/genstore/") {
			return
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok ||
				(selector.Sel.Name != "OpenHistoricalGenerationEnvelope" &&
					selector.Sel.Name != "VerifyHistoricalGenerationSealIntegrity") {
				return true
			}
			t.Errorf(
				"%s calls %s directly; historical term access must pass through internal/genstore",
				rel,
				selector.Sel.Name,
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
