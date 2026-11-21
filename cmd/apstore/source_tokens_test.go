// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func activeStoreForTokenTest(t *testing.T, root string, passphrase []byte) (storepaths.GenPaths, *crypto.Keyring) {
	t.Helper()
	active, kr, err := genstore.ResolveStoreRoot(storepaths.NewPaths(root), passphrase)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kr.Zero)
	return active, kr
}

func tokenFileForApstoreTest(t *testing.T, selector, token string) *sourcetokens.File {
	t.Helper()
	f, err := sourcetokens.SetToken(nil, selector, "screening", []byte(token), time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// A token file that no longer decrypts fails every load, so the daemon stays
// in recovery. Discard deletes it without reading it and archives nothing;
// the tokens load again, and the selector has no token, so its sources
// refuse with token_not_set.
func TestCmdSourceTokenDiscardRemovesADamagedTokenFile(t *testing.T) {
	withPolicyCommandStoreWithRole(t, noderole.RoleCosigner, func(root string, passphrase []byte) {
		active, kr := activeStoreForTokenTest(t, root, passphrase)
		if err := os.WriteFile(active.SourceTokenPath(sourcetokens.DefaultSelector), []byte(`{"envelope_version":3,"term":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := sourcetokens.LoadIndex(active, noderole.RoleCosigner, kr); err == nil {
			t.Fatal("a damaged token file loaded")
		}

		if err := withTestStdin(string(passphrase)+"\n", func() error {
			return cmdSource([]string{"token", "discard", sourcetokens.DefaultSelector, "--yes"})
		}); err != nil {
			t.Fatalf("cmdSource(discard) error = %v", err)
		}
		if _, err := os.Lstat(active.SourceTokenPath(sourcetokens.DefaultSelector)); !os.IsNotExist(err) {
			t.Fatalf("the damaged token file survived: %v", err)
		}
		if archived, err := os.ReadDir(active.DeletedSourceTokensDir()); err != nil || len(archived) != 0 {
			t.Fatalf("discard archived something: %v, %v", archived, err)
		}
		index, err := sourcetokens.LoadIndex(active, noderole.RoleCosigner, kr)
		if err != nil {
			t.Fatalf("the tokens still fail to load: %v", err)
		}
		if _, ok := index.TokenFor(sourcetokens.DefaultSelector, "screening"); ok {
			t.Fatal("the discarded selector still has a token")
		}
	})
}

// Discard asks first and changes nothing when the answer is no; a selector
// without a file discards nothing.
func TestCmdSourceTokenDiscardAsksAndKeepsAFileItWasNotToldToDiscard(t *testing.T) {
	withPolicyCommandStoreWithRole(t, noderole.RoleCosigner, func(root string, passphrase []byte) {
		active, kr := activeStoreForTokenTest(t, root, passphrase)
		f := tokenFileForApstoreTest(t, sourcetokens.DefaultSelector, "tok-kept")
		defer f.Zero()
		if err := sourcetokens.WriteFile(active, f, kr); err != nil {
			t.Fatal(err)
		}
		err := withTestStdin("n\n", func() error {
			return cmdSource([]string{"token", "discard", sourcetokens.DefaultSelector})
		})
		if err == nil || !strings.Contains(err.Error(), "discard cancelled") {
			t.Fatalf("cmdSource(discard, declined) error = %v", err)
		}
		if _, ok, err := sourcetokens.ReadFile(active, sourcetokens.DefaultSelector, kr); err != nil || !ok {
			t.Fatalf("a declined discard removed the file: %v, %v", ok, err)
		}

		const absent = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"
		if err := withTestStdin(string(passphrase)+"\n", func() error {
			return cmdSource([]string{"token", "discard", absent, "--yes"})
		}); err != nil {
			t.Fatalf("cmdSource(discard, no file) error = %v", err)
		}
	})
}

// A malformed discard is a usage error, and discard takes the store's
// exclusive lock, so it never runs beside the daemon.
func TestCmdSourceTokenDiscardUsageAndLock(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"token"},
		{"token", "remove", "default"},
		{"token", "discard", "not-a-selector"},
		{"token", "discard", "default", "--force"},
		{"token", "discard", "default", "--yes", "--yes"},
	} {
		if err := cmdSource(args); err == nil || exitCodeForError(err) != apstoreExitUsage {
			t.Fatalf("cmdSource(%q) error = %v, want a usage error", args, err)
		}
	}
	if !isOfflineMutatingCommand("source") {
		t.Fatal("source token discard does not take the exclusive store lock")
	}
}

// Rebuild writes each rebuilt cosigner key's archived tokens as its token
// file in the new store, which validates as a first generation.
func TestCmdRebuildWritesTheKeysSourceTokens(t *testing.T) {
	RegisterProviders()
	oldDataDirectory, oldReader := dataDirectory, stdinReader
	dataDirectory, stdinReader = t.TempDir(), nil
	t.Setenv("APSIGNER_PASSPHRASE", "")
	defer func() { dataDirectory, stdinReader = oldDataDirectory, oldReader }()

	backupRoot := t.TempDir()
	componentKey, keyJSON := testCosignerComponentKeyJSONForApstore(t)
	if err := writeStandaloneBackup(filepath.Join(backupRoot, "apb"), componentKey, keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatal(err)
	}
	f := tokenFileForApstoreTest(t, componentKey, "tok-rebuilt")
	tokens, err := sourcetokens.Encode(f)
	f.Zero()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeStandaloneBackup(filepath.Join(backupRoot, "source_tokens"), componentKey, tokens, []byte("export-passphrase")); err != nil {
		t.Fatal(err)
	}
	if err := backup.WriteReadme(backupRoot); err != nil {
		t.Fatal(err)
	}
	sealTestArchive(t, backupRoot, noderole.RoleCosigner)
	archivePath := filepath.Join(t.TempDir(), "cosigner-rebuild.tar.gz")
	if err := backup.CreateTarGzArchive(backupRoot, archivePath); err != nil {
		t.Fatal(err)
	}

	if err := withTestStdin("export-passphrase\nnew-store-passphrase\nnew-store-passphrase\n", func() error {
		return cmdRebuild([]string{archivePath})
	}); err != nil {
		t.Fatalf("cmdRebuild() error = %v", err)
	}
	active, kr := activeStoreForTokenTest(t, dataDirectory, []byte("new-store-passphrase"))
	rebuilt, ok, err := sourcetokens.ReadFile(active, componentKey, kr)
	if err != nil || !ok || string(rebuilt.Tokens["screening"].Value) != "tok-rebuilt" {
		t.Fatalf("rebuilt token file = %v, %v", ok, err)
	}
	rebuilt.Zero()
}
