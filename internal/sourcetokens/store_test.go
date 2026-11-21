// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sourcetokens

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keyclass"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func testGeneration(t *testing.T) (storepaths.GenPaths, *crypto.Keyring) {
	t.Helper()
	kr, active := genstoretest.MintFirstAtomic(t, storepaths.NewPaths(t.TempDir()), []byte("sourcetokens-test-passphrase"))
	t.Cleanup(kr.Zero)
	return active, kr
}

func TestWriteReadRemoveRoundTrip(t *testing.T) {
	active, kr := testGeneration(t)
	if _, ok, err := ReadFile(active, testKeyID, kr); err != nil || ok {
		t.Fatalf("ReadFile(no file) = %v, %v", ok, err)
	}
	f := mustSet(t, nil, testKeyID, "ops", "first")
	if err := WriteFile(active, f, kr); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	info, err := os.Stat(active.SourceTokenPath(testKeyID))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("token file = %v, %v; want mode 0600", info, err)
	}
	got, ok, err := ReadFile(active, testKeyID, kr)
	if err != nil || !ok || string(got.Tokens["ops"].Value) != "first" {
		t.Fatalf("ReadFile() = %+v, %v, %v", got, ok, err)
	}
	if selectors, err := Selectors(active); err != nil || len(selectors) != 1 || selectors[0] != testKeyID {
		t.Fatalf("Selectors() = %v, %v", selectors, err)
	}
	if err := RemoveFile(active, testKeyID); err != nil {
		t.Fatalf("RemoveFile() error = %v", err)
	}
	if _, ok, err := ReadFile(active, testKeyID, kr); err != nil || ok {
		t.Fatalf("ReadFile(after remove) = %v, %v", ok, err)
	}
	// Removing a selector's file never archives it.
	if entries, err := os.ReadDir(active.DeletedSourceTokensDir()); err != nil || len(entries) != 0 {
		t.Fatalf("deleted source tokens after a remove = %v, %v", entries, err)
	}
}

func TestWriteFileRefusesAnOversizeFileBeforeWriting(t *testing.T) {
	active, kr := testGeneration(t)
	f := mustSet(t, nil, testKeyID, "s0", strings.Repeat("a", MaxTokenBytes))
	f = mustSet(t, f, testKeyID, "s1", strings.Repeat("b", MaxTokenBytes))
	if err := WriteFile(active, f, kr); err != nil {
		t.Fatal(err)
	}
	bigger := mustSet(t, f, testKeyID, "s2", strings.Repeat("c", MaxTokenBytes))
	if err := WriteFile(active, bigger, kr); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("WriteFile(oversize) error = %v, want ErrFileTooLarge", err)
	}
	got, _, err := ReadFile(active, testKeyID, kr)
	if err != nil || len(got.Tokens) != 2 {
		t.Fatalf("file after the refused write = %+v, %v; want the two tokens it had", got.Listing(), err)
	}
}

func TestLoadFilesChecksEveryFile(t *testing.T) {
	tests := map[string]func(t *testing.T, active storepaths.GenPaths, kr *crypto.Keyring){
		"a file renamed to another key": func(t *testing.T, active storepaths.GenPaths, kr *crypto.Keyring) {
			writeTestFile(t, active, kr, testKeyID)
			if err := os.Rename(active.SourceTokenPath(testKeyID), active.SourceTokenPath(otherTestKeyID)); err != nil {
				t.Fatal(err)
			}
		},
		"a file renamed to the default": func(t *testing.T, active storepaths.GenPaths, kr *crypto.Keyring) {
			writeTestFile(t, active, kr, testKeyID)
			if err := os.Rename(active.SourceTokenPath(testKeyID), active.SourceTokenPath(DefaultSelector)); err != nil {
				t.Fatal(err)
			}
		},
		"another class under the token file's name": func(t *testing.T, active storepaths.GenPaths, kr *crypto.Keyring) {
			sealed, err := kr.Seal([]byte("{}"), crypto.CosignerCredentialContext(testKeyID))
			if err != nil {
				t.Fatal(err)
			}
			writeRaw(t, active.SourceTokenPath(testKeyID), sealed)
		},
		"a damaged file": func(t *testing.T, active storepaths.GenPaths, kr *crypto.Keyring) {
			writeTestFile(t, active, kr, testKeyID)
			data, err := os.ReadFile(active.SourceTokenPath(testKeyID))
			if err != nil {
				t.Fatal(err)
			}
			data[len(data)-4] ^= 1
			writeRaw(t, active.SourceTokenPath(testKeyID), data)
		},
		"plaintext": func(t *testing.T, active storepaths.GenPaths, _ *crypto.Keyring) {
			writeRaw(t, active.SourceTokenPath(testKeyID), []byte(`{"format":"aplane.source-tokens.v1"}`))
		},
		"an oversize file": func(t *testing.T, active storepaths.GenPaths, _ *crypto.Keyring) {
			writeRaw(t, active.SourceTokenPath(testKeyID), bytes.Repeat([]byte(" "), MaxFileBytes+1))
		},
		"a non-canonical name": func(t *testing.T, active storepaths.GenPaths, _ *crypto.Keyring) {
			writeRaw(t, filepath.Join(active.SourceTokensDir(), "screening.enc"), []byte("x"))
		},
		"an address-named file": func(t *testing.T, active storepaths.GenPaths, _ *crypto.Keyring) {
			writeRaw(t, filepath.Join(active.SourceTokensDir(), "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM.enc"), []byte("x"))
		},
		"another extension": func(t *testing.T, active storepaths.GenPaths, _ *crypto.Keyring) {
			writeRaw(t, filepath.Join(active.SourceTokensDir(), testKeyID+".json"), []byte("x"))
		},
		"write residue": func(t *testing.T, active storepaths.GenPaths, kr *crypto.Keyring) {
			writeTestFile(t, active, kr, testKeyID)
			writeRaw(t, active.SourceTokenPath(testKeyID)+".tmp-123", []byte("x"))
		},
		"a directory": func(t *testing.T, active storepaths.GenPaths, _ *crypto.Keyring) {
			if err := os.Mkdir(active.SourceTokenPath(testKeyID), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"a symlink": func(t *testing.T, active storepaths.GenPaths, kr *crypto.Keyring) {
			writeTestFile(t, active, kr, testKeyID)
			if err := os.Symlink(active.SourceTokenPath(testKeyID), active.SourceTokenPath(otherTestKeyID)); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, damage := range tests {
		t.Run(name, func(t *testing.T) {
			active, kr := testGeneration(t)
			damage(t, active, kr)
			if files, err := LoadFiles(active, noderole.RoleCosigner, kr); err == nil {
				t.Fatalf("LoadFiles() accepted %s: %d files", name, len(files))
			}
		})
	}
}

func TestLoadFilesIsARoleConflictOnASignerNode(t *testing.T) {
	active, kr := testGeneration(t)
	if files, err := LoadFiles(active, noderole.RoleSigner, kr); err != nil || len(files) != 0 {
		t.Fatalf("LoadFiles(signer, none) = %d, %v", len(files), err)
	}
	writeTestFile(t, active, kr, DefaultSelector)
	if _, err := LoadFiles(active, noderole.RoleSigner, kr); !errors.Is(err, keyclass.ErrNodeRoleConflict) {
		t.Fatalf("LoadFiles(signer with a token file) error = %v, want a node role conflict", err)
	}
	files, err := LoadFiles(active, noderole.RoleCosigner, kr)
	if err != nil || len(files) != 1 || files[0].Selector != DefaultSelector {
		t.Fatalf("LoadFiles(cosigner) = %d, %v", len(files), err)
	}
}

func TestLoadIndexHoldsEverySelectorsTokens(t *testing.T) {
	active, kr := testGeneration(t)
	writeTestFile(t, active, kr, testKeyID)
	f := mustSet(t, nil, DefaultSelector, "ops", "default-token")
	if err := WriteFile(active, f, kr); err != nil {
		t.Fatal(err)
	}
	x, err := LoadIndex(active, noderole.RoleCosigner, kr)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct{ selector, source, token string }{
		{testKeyID, "ops", "token-of-" + testKeyID[:4]},
		{DefaultSelector, "ops", "default-token"},
	} {
		if got, ok := x.TokenFor(want.selector, want.source); !ok || got != want.token {
			t.Fatalf("TokenFor(%s, %s) = %q, %v", want.selector, want.source, got, ok)
		}
	}
	if _, ok := x.TokenFor(otherTestKeyID, "ops"); ok {
		t.Fatal("TokenFor() found a token for a selector with none")
	}
}

func TestArchiveMovesTheFileAndVerifiesThere(t *testing.T) {
	active, kr := testGeneration(t)
	if err := Archive(active, testKeyID); err != nil {
		t.Fatalf("Archive(no file) error = %v", err)
	}
	if path, ok, err := ArchivePath(active, "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM"); err != nil || ok || path != "" {
		t.Fatalf("ArchivePath(address) = %q, %v, %v", path, ok, err)
	}
	writeTestFile(t, active, kr, testKeyID)
	if path, ok, err := ArchivePath(active, testKeyID); err != nil || !ok || path != active.SourceTokenPath(testKeyID) {
		t.Fatalf("ArchivePath() = %q, %v, %v", path, ok, err)
	}
	if err := Archive(active, testKeyID); err != nil {
		t.Fatalf("Archive() error = %v", err)
	}
	if _, err := os.Stat(active.SourceTokenPath(testKeyID)); !os.IsNotExist(err) {
		t.Fatalf("active file survived the archive: %v", err)
	}
	if err := VerifyArchived(active, testKeyID+storepaths.SourceTokenFileExtension, kr); err != nil {
		t.Fatalf("VerifyArchived() error = %v", err)
	}
	if err := os.Rename(active.DeletedSourceTokenPath(testKeyID), active.DeletedSourceTokenPath(otherTestKeyID)); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArchived(active, otherTestKeyID+storepaths.SourceTokenFileExtension, kr); err == nil {
		t.Fatal("VerifyArchived() opened a file renamed to another key")
	}
	if err := VerifyArchived(active, "screening.enc", kr); err == nil {
		t.Fatal("VerifyArchived() accepted a non-canonical name")
	}
}

func writeTestFile(t *testing.T, active storepaths.GenPaths, kr *crypto.Keyring, selector string) {
	t.Helper()
	f := mustSet(t, nil, selector, "ops", "token-of-"+selector[:4])
	if err := WriteFile(active, f, kr); err != nil {
		t.Fatal(err)
	}
}

func writeRaw(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
