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

// inadmissibleKeyForApstore is a credential this release cannot admit, and
// why a restore skips it.
type inadmissibleKeyForApstore struct {
	name, selector string
	keyJSON        []byte
	reason         string
}

// inadmissibleKeysForApstore are a payload with a field this release does
// not know, a key file written before salt_counter was retired, and native
// Falcon key files written before pq_scheme and pq_address_salt were
// dropped, with and without recovery entropy.
func inadmissibleKeysForApstore(t *testing.T) []inadmissibleKeyForApstore {
	t.Helper()
	RegisterProviders()
	unknown, unknownJSON := testEd25519KeyJSON(t)
	var object map[string]json.RawMessage
	if err := json.Unmarshal(unknownJSON, &object); err != nil {
		t.Fatal(err)
	}
	object["extra"] = json.RawMessage("1")
	extended, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	retired, retiredJSON := keystest.RetiredSaltCounterLSigKeyJSON(t)
	falcon, falconJSON := keystest.NativeFalconKeyJSON(t, bytes.Repeat([]byte{0xa1}, 32))
	noEntropy, noEntropyJSON := keystest.NativeFalconKeyJSON(t, bytes.Repeat([]byte{0xa2}, 32))
	const preChangeNativeFalcon = `failed to parse backup credential: incompatible key file format: failed to decode canonical payload: json: unknown field "pq_scheme"; restore or regenerate the key file using the current key schema`
	return []inadmissibleKeyForApstore{
		{"unknown field", unknown, extended, `failed to parse backup credential: incompatible key file format: failed to decode canonical payload: json: unknown field "extra"; restore or regenerate the key file using the current key schema`},
		{"retired salt_counter", retired, retiredJSON, `failed to parse backup credential: incompatible key file format: failed to decode canonical payload: json: unknown field "salt_counter"; restore or regenerate the key file using the current key schema`},
		{"native Falcon with pq_scheme and pq_address_salt", falcon, keystest.PreChangeNativeFalconKeyJSON(t, falconJSON, true), preChangeNativeFalcon},
		{"native Falcon without recovery entropy", noEntropy, keystest.PreChangeNativeFalconKeyJSON(t, noEntropyJSON, false), preChangeNativeFalcon},
	}
}

// writeMixedArchiveForApstore writes an archive holding one credential this
// release admits and bad, which it cannot.
func writeMixedArchiveForApstore(t *testing.T, bad inadmissibleKeyForApstore) (archivePath, good string) {
	t.Helper()
	root := t.TempDir()
	good, goodJSON := testEd25519KeyJSON(t)
	for selector, keyJSON := range map[string][]byte{good: goodJSON, bad.selector: bad.keyJSON} {
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
	return archivePath, good
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
	for _, bad := range inadmissibleKeysForApstore(t) {
		t.Run(bad.name, func(t *testing.T) {
			archivePath, good := writeMixedArchiveForApstore(t, bad)
			log := captureApstoreLog(t)
			err := withTestStdin("export-passphrase\n", func() error { return cmdVerify(archivePath) })
			var coded codedError
			wantMessage := "1 of 2 credentials would be skipped by restore; first " + bad.selector + ": " + bad.reason
			if !errors.As(err, &coded) || coded.code != "verification_failed" || coded.message != wantMessage {
				t.Fatalf("cmdVerify() error = %v, want verification_failed: %s", err, wantMessage)
			}
			for _, want := range []string{good + ".apb (ed25519, decrypts OK)", bad.selector + ".apb - restore would skip it: " + bad.reason} {
				if !strings.Contains(log.String(), want) {
					t.Fatalf("%q missing from:\n%s", want, log.String())
				}
			}
		})
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
	for _, bad := range inadmissibleKeysForApstore(t) {
		t.Run(bad.name, func(t *testing.T) {
			archivePath, good := writeMixedArchiveForApstore(t, bad)
			log := captureApstoreLog(t)
			if err := rebuildForApstoreTest(t, "export-passphrase\nnew-store-passphrase\nnew-store-passphrase\n", archivePath); err != nil {
				t.Fatalf("cmdRebuild() error = %v", err)
			}
			for _, want := range []string{"skipping " + bad.selector + ": " + bad.reason, "rebuilt: " + good + " (ed25519)", "1 key(s) rebuilt, 1 skipped"} {
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
			if _, err := os.Stat(keystest.AccountKeyFilePath(active, bad.selector)); !os.IsNotExist(err) {
				t.Fatalf("skipped key file was written: %v", err)
			}
		})
	}
}

// A rebuild that names the key this release cannot admit, or leaves nothing
// to rebuild, is refused before it asks for a store passphrase, and lists
// what it would skip.
func TestCmdRebuildRefusesWhatItWouldSkip(t *testing.T) {
	RegisterProviders()
	unknownField := inadmissibleKeysForApstore(t)[0]
	archivePath, good := writeMixedArchiveForApstore(t, unknownField)
	bad := unknownField.selector
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
