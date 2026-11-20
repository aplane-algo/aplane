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

// Verify lists the key this release cannot admit with its reason and fails.
func TestCmdVerifyReportsAnInadmissibleKey(t *testing.T) {
	RegisterProviders()
	archivePath, good, bad := writeMixedArchiveForApstore(t)
	log := captureApstoreLog(t)
	err := withTestStdin("export-passphrase\n", func() error { return cmdVerify(archivePath) })
	var coded codedError
	if !errors.As(err, &coded) || coded.code != "verification_failed" || coded.message != "1 credential file(s) failed validation" {
		t.Fatalf("cmdVerify() error = %v, want verification_failed", err)
	}
	for _, want := range []string{good + ".apb (ed25519, decrypts OK)", bad + ".apb - " + unknownFieldReasonForApstore} {
		if !strings.Contains(log.String(), want) {
			t.Fatalf("%q missing from:\n%s", want, log.String())
		}
	}
}

// A rebuild from an archive holding a key this release cannot admit is
// refused before it asks for a store passphrase.
func TestCmdRebuildOfAnArchiveWithAnInadmissibleKey(t *testing.T) {
	RegisterProviders()
	oldDataDirectory := dataDirectory
	dataDirectory = t.TempDir()
	t.Cleanup(func() { dataDirectory = oldDataDirectory })
	t.Setenv("APSIGNER_PASSPHRASE", "")
	archivePath, _, _ := writeMixedArchiveForApstore(t)
	err := withTestStdin("export-passphrase\n", func() error { return cmdRebuild([]string{archivePath}) })
	if err == nil || err.Error() != "failed to verify rebuild backup: 1 file(s) failed deep verification" {
		t.Fatalf("cmdRebuild() error = %v", err)
	}
	if _, statErr := os.Stat(keystorePaths().ProductDir()); !os.IsNotExist(statErr) {
		t.Fatalf("refused rebuild left an identity directory: %v", statErr)
	}
}
