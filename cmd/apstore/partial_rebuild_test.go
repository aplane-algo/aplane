// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/noderole"
)

// unknownFieldReasonForApstore is why this release refuses a payload with a
// field it does not know.
const unknownFieldReasonForApstore = `failed to parse backup credential: incompatible key file format: failed to decode canonical payload: json: unknown field "extra"; restore or regenerate the key file using the current key schema`

// writeMixedArchiveForApstore writes an archive holding one credential this
// release admits and one whose payload carries a field it does not know.
func writeMixedArchiveForApstore(t *testing.T) (archivePath, good, bad string) {
	t.Helper()
	root := t.TempDir()
	good, goodJSON := testEd25519KeyJSON(t)
	bad, badJSON := testEd25519KeyJSON(t)
	var object map[string]json.RawMessage
	if err := json.Unmarshal(badJSON, &object); err != nil {
		t.Fatal(err)
	}
	object["extra"] = json.RawMessage("1")
	extended, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	for selector, keyJSON := range map[string][]byte{good: goodJSON, bad: extended} {
		if err := writeStandaloneBackup(filepath.Join(root, "apb"), selector, keyJSON, []byte("export-passphrase")); err != nil {
			t.Fatal(err)
		}
	}
	if err := backup.WriteReadme(root); err != nil {
		t.Fatal(err)
	}
	sealTestArchive(t, root, noderole.RoleSigner)
	archivePath = filepath.Join(t.TempDir(), "mixed.tar.gz")
	if err := backup.CreateTarGzArchive(root, archivePath); err != nil {
		t.Fatal(err)
	}
	return archivePath, good, bad
}

// captureApstoreLog sends apstore's log to a buffer for the test.
func captureApstoreLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	appLogger.SetOutput(&buf)
	t.Cleanup(func() { appLogger.SetOutput(os.Stderr) })
	return &buf
}

// Verify lists every key a restore would skip, with the reason, and fails.
func TestCmdVerifyReportsAnInadmissibleKey(t *testing.T) {
	RegisterProviders()
	archivePath, good, bad := writeMixedArchiveForApstore(t)
	log := captureApstoreLog(t)
	err := withTestStdin("export-passphrase\n", func() error { return cmdVerify(archivePath) })
	var coded codedError
	wantMessage := "1 of 2 credentials would be skipped by restore; first " + bad + ": " + unknownFieldReasonForApstore
	if !errors.As(err, &coded) || coded.code != "verification_failed" || coded.message != wantMessage {
		t.Fatalf("cmdVerify() error = %v, want verification_failed: %s", err, wantMessage)
	}
	for _, want := range []string{good + ".apb (ed25519, decrypts OK)", bad + ".apb - restore would skip it: " + unknownFieldReasonForApstore} {
		if !strings.Contains(log.String(), want) {
			t.Fatalf("%q missing from:\n%s", want, log.String())
		}
	}
}

// rebuildForApstoreTest runs a rebuild in a fresh data directory with input
// on stdin.
func rebuildForApstoreTest(t *testing.T, input string, args ...string) error {
	t.Helper()
	oldDataDirectory := dataDirectory
	dataDirectory = t.TempDir()
	t.Cleanup(func() { dataDirectory = oldDataDirectory })
	t.Setenv("APSIGNER_PASSPHRASE", "")
	return withTestStdin(input, func() error { return cmdRebuild(args) })
}

// A rebuild skips the key this release cannot admit, says so, and rebuilds
// the rest.
func TestCmdRebuildSkipsAnInadmissibleKey(t *testing.T) {
	RegisterProviders()
	archivePath, good, bad := writeMixedArchiveForApstore(t)
	log := captureApstoreLog(t)
	if err := rebuildForApstoreTest(t, "export-passphrase\nnew-store-passphrase\nnew-store-passphrase\n", archivePath); err != nil {
		t.Fatalf("cmdRebuild() error = %v", err)
	}
	for _, want := range []string{"skipping " + bad + ": " + unknownFieldReasonForApstore, "rebuilt: " + good + " (ed25519)", "1 key(s) rebuilt, 1 skipped"} {
		if !strings.Contains(log.String(), want) {
			t.Fatalf("%q missing from:\n%s", want, log.String())
		}
	}
	active, kr, err := genstore.ResolveStoreRoot(keystorePaths(), []byte("new-store-passphrase"))
	if err != nil {
		t.Fatalf("ResolveStoreRoot() error = %v", err)
	}
	defer kr.Zero()
	if _, err := os.Stat(keystest.AccountKeyFilePath(active, good)); err != nil {
		t.Fatalf("rebuilt key file missing: %v", err)
	}
	if _, err := os.Stat(keystest.AccountKeyFilePath(active, bad)); !os.IsNotExist(err) {
		t.Fatalf("skipped key file was written: %v", err)
	}
}

// A rebuild that names the key this release cannot admit, or leaves nothing
// to rebuild, is refused before it asks for a store passphrase, and lists
// what it would skip.
func TestCmdRebuildRefusesWhatItWouldSkip(t *testing.T) {
	RegisterProviders()
	archivePath, good, bad := writeMixedArchiveForApstore(t)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"naming it", []string{archivePath, "--address", good, "--address", bad}, "rebuild refused: selected credential cannot be restored: " + bad + ": "},
		{"nothing left", []string{archivePath, "--role", "cosigner"}, "rebuild refused: nothing to restore: all 2 credentials in the backup are skipped; first "},
	} {
		log := captureApstoreLog(t)
		err := rebuildForApstoreTest(t, "export-passphrase\n", tc.args...)
		if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
			t.Fatalf("%s: cmdRebuild() error = %v, want prefix %q", tc.name, err, tc.want)
		}
		if !strings.Contains(log.String(), "skipping "+bad+": ") {
			t.Fatalf("%s: the skipped key is not reported:\n%s", tc.name, log.String())
		}
		for _, path := range []string{keystorePaths().ProductDir(), keystorePaths().NodeRolePath()} {
			if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
				t.Fatalf("%s: refused rebuild left %s: %v", tc.name, path, statErr)
			}
		}
	}
}
