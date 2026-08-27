// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestResolveStoreRootUsesAuthenticatedSelection(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	mintTestGeneration(t, paths, testGenA, map[string]string{"keys/A.key": "a"})
	mintTestGeneration(t, paths, testGenB, map[string]string{"keys/B.key": "b"})
	passphrase := []byte("passphrase")
	kr, err := crypto.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	root, err := crypto.SealStoreRoot(kr, passphrase, testGenA)
	if err != nil {
		t.Fatal(err)
	}
	writeTestStoreRootLayout(t, paths, root)

	gen, opened, err := ResolveStoreRoot(paths, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Zero()
	if gen.GenerationID() != testGenA {
		t.Fatalf("resolved generation = %s, want authenticated %s", gen.GenerationID(), testGenA)
	}
}

func TestResolveStoreRootFailsClosedOnMissingSelectedGeneration(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	passphrase := []byte("passphrase")
	kr, err := crypto.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	root, err := crypto.SealStoreRoot(kr, passphrase, testGenA)
	if err != nil {
		t.Fatal(err)
	}
	writeTestStoreRootLayout(t, paths, root)
	if _, opened, err := ResolveStoreRoot(paths, passphrase); err == nil || opened != nil {
		t.Fatalf("ResolveStoreRoot(missing generation) = (%v, %v)", opened, err)
	}
}

func writeTestStoreRootLayout(t *testing.T, paths storepaths.Paths, root []byte) {
	t.Helper()
	if err := os.MkdirAll(paths.ProductDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	marker, err := json.Marshal(map[string]any{
		"version": crypto.StoreRootKeystoreMetadataVersion,
		"layout":  crypto.KeystoreLayoutStoreRootV1,
		"created": "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fsutil.WriteFileDurable(filepath.Join(paths.ProductDir(), ".keystore"), marker); err != nil {
		t.Fatal(err)
	}
	if err := fsutil.WriteFileDurable(paths.StoreRootPath(), root); err != nil {
		t.Fatal(err)
	}
}
