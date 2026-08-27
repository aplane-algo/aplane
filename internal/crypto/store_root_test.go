// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const (
	testStoreRootGenerationA = "gen-1700000000-0123abcd"
	testStoreRootGenerationB = "gen-1700000001-4567abcd"
)

func TestStoreRootSealOpenRoundTrip(t *testing.T) {
	passphrase := []byte("correct horse battery staple")
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	encoded, err := SealStoreRoot(kr, passphrase, testStoreRootGenerationA)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.HasSuffix(encoded, []byte("\n")) {
		t.Fatal("store root is not canonical compact JSON")
	}
	opened, selection, err := OpenStoreRoot(encoded, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Zero()
	if selection.CurrentGenerationID != testStoreRootGenerationA ||
		selection.SelectionTerm != FirstTerm ||
		opened.CurrentTerm() != FirstTerm {
		t.Fatalf("opened selection = %+v term=%d", selection, opened.CurrentTerm())
	}

	sealed, err := kr.Seal([]byte("secret"), AccountKeyContext("ADDR"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := opened.Open(sealed, AccountKeyContext("ADDR"))
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(plaintext)
	if string(plaintext) != "secret" {
		t.Fatalf("opened plaintext = %q", plaintext)
	}
	if _, _, err := OpenStoreRoot(encoded, []byte("wrong passphrase")); err == nil {
		t.Fatal("OpenStoreRoot accepted a wrong passphrase")
	}
}

func TestStoreRootMultiTermAnchoredKeyringRoundTrip(t *testing.T) {
	base, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer base.Zero()
	anchors := []HistoricalGenerationAnchor{{
		GenerationID: testStoreRootGenerationA,
		SealSize:     123,
		SealSHA256:   strings.Repeat("a", sha256HexLength),
	}}
	successor, err := NewSuccessorKeyring(base, anchors)
	if err != nil {
		t.Fatal(err)
	}
	defer successor.Zero()
	encoded, err := SealStoreRoot(successor, []byte("new passphrase"), testStoreRootGenerationB)
	if err != nil {
		t.Fatal(err)
	}
	opened, selection, err := OpenStoreRoot(encoded, []byte("new passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Zero()
	if selection.SelectionTerm != FirstTerm+1 || len(opened.terms) != 2 {
		t.Fatalf("opened selection=%+v terms=%d", selection, len(opened.terms))
	}
	if got, ok := opened.HistoricalGenerationAnchor(testStoreRootGenerationA); !ok || got != anchors[0] {
		t.Fatalf("anchor = %+v, %t", got, ok)
	}
}

func TestStoreRootRejectsOversizeWrappedKeyring(t *testing.T) {
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	root, err := SealStoreRoot(kr, []byte("passphrase"), testStoreRootGenerationA)
	if err != nil {
		t.Fatal(err)
	}
	var file storeRootFile
	if err := json.Unmarshal(root, &file); err != nil {
		t.Fatal(err)
	}
	file.Keyring = json.RawMessage(`{"schema":"aplane.keyring.v3","padding":"` + strings.Repeat("x", maxKeyringBytes) + `"}`)
	oversize, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenStoreRoot(oversize, []byte("passphrase")); err == nil || !strings.Contains(err.Error(), "keyring") {
		t.Fatalf("OpenStoreRoot(oversize) error = %v", err)
	}
}

func TestStoreRootReselectPreservesExactWrappedKeyring(t *testing.T) {
	passphrase := []byte("passphrase")
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	original, err := SealStoreRoot(kr, passphrase, testStoreRootGenerationA)
	if err != nil {
		t.Fatal(err)
	}
	before, err := parseStoreRoot(original)
	if err != nil {
		t.Fatal(err)
	}
	reselected, err := ReselectStoreRoot(original, kr, testStoreRootGenerationB)
	if err != nil {
		t.Fatal(err)
	}
	after, err := parseStoreRoot(reselected)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before.Keyring, after.Keyring) {
		t.Fatal("ordinary reselection changed the wrapped keyring bytes")
	}
	if before.SelectionMAC == after.SelectionMAC {
		t.Fatal("generation reselection did not change the selection MAC")
	}
	opened, selection, err := OpenStoreRoot(reselected, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Zero()
	if selection.CurrentGenerationID != testStoreRootGenerationB {
		t.Fatalf("selected generation = %q", selection.CurrentGenerationID)
	}
}

func TestStoreRootRejectsWrappedKeyringSelectorMixAndMatch(t *testing.T) {
	passphrase := []byte("same passphrase")
	firstKeyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer firstKeyring.Zero()
	secondKeyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer secondKeyring.Zero()
	first, err := SealStoreRoot(firstKeyring, passphrase, testStoreRootGenerationA)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SealStoreRoot(secondKeyring, passphrase, testStoreRootGenerationB)
	if err != nil {
		t.Fatal(err)
	}
	firstFile, err := parseStoreRoot(first)
	if err != nil {
		t.Fatal(err)
	}
	secondFile, err := parseStoreRoot(second)
	if err != nil {
		t.Fatal(err)
	}
	firstFile.Keyring = secondFile.Keyring
	mixed, err := json.Marshal(firstFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenStoreRoot(mixed, passphrase); err == nil ||
		!strings.Contains(err.Error(), "selection MAC") {
		t.Fatalf("OpenStoreRoot(mixed) error = %v", err)
	}
}

func TestStoreRootReselectRejectsStaleOrUnrelatedAuthority(t *testing.T) {
	passphrase := []byte("passphrase")
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	root, err := SealStoreRoot(kr, passphrase, testStoreRootGenerationA)
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer unrelated.Zero()
	if _, err := ReselectStoreRoot(root, unrelated, testStoreRootGenerationB); err == nil ||
		!strings.Contains(err.Error(), "selection MAC") {
		t.Fatalf("ReselectStoreRoot(unrelated) error = %v", err)
	}
	parsed, err := parseStoreRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	parsed.CurrentGenerationID = testStoreRootGenerationB
	tampered, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReselectStoreRoot(tampered, kr, testStoreRootGenerationA); err == nil ||
		!strings.Contains(err.Error(), "selection MAC") {
		t.Fatalf("ReselectStoreRoot(tampered fresh read) error = %v", err)
	}
}

func TestStoreRootRejectedSelectionZeroesDecodedTermKeys(t *testing.T) {
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	root, err := SealStoreRoot(kr, []byte("passphrase"), testStoreRootGenerationA)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseStoreRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	parsed.CurrentGenerationID = testStoreRootGenerationB
	tampered, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	var decodedTerms []sealedTerm
	keyringDecodeHook = func(terms []sealedTerm) { decodedTerms = terms }
	defer func() { keyringDecodeHook = nil }()
	if _, _, err := OpenStoreRoot(tampered, []byte("passphrase")); err == nil {
		t.Fatal("OpenStoreRoot accepted tampered selection")
	}
	if len(decodedTerms) == 0 {
		t.Fatal("test hook did not observe decoded terms")
	}
	for _, term := range decodedTerms {
		if !bytes.Equal(term.Key, make([]byte, len(term.Key))) {
			t.Fatalf("decoded term %d was not zeroed", term.Term)
		}
	}
}

func TestStoreRootStrictCanonicalParsing(t *testing.T) {
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	encoded, err := SealStoreRoot(kr, []byte("passphrase"), testStoreRootGenerationA)
	if err != nil {
		t.Fatal(err)
	}
	var valid storeRootFile
	if err := json.Unmarshal(encoded, &valid); err != nil {
		t.Fatal(err)
	}
	mutate := func(t *testing.T, fn func(*storeRootFile)) []byte {
		t.Helper()
		candidate := valid
		candidate.Keyring = bytes.Clone(valid.Keyring)
		fn(&candidate)
		data, err := json.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	withUnknown := func(t *testing.T) []byte {
		t.Helper()
		var object map[string]any
		if err := json.Unmarshal(encoded, &object); err != nil {
			t.Fatal(err)
		}
		object["unexpected"] = true
		data, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	withReorderedOuter := func(t *testing.T) []byte {
		t.Helper()
		var object map[string]any
		if err := json.Unmarshal(encoded, &object); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	withBadKeyringHeader := func(t *testing.T, field string, value any) []byte {
		t.Helper()
		var keyring map[string]any
		if err := json.Unmarshal(valid.Keyring, &keyring); err != nil {
			t.Fatal(err)
		}
		keyring[field] = value
		wrapped, err := json.Marshal(keyring)
		if err != nil {
			t.Fatal(err)
		}
		return mutate(t, func(root *storeRootFile) { root.Keyring = wrapped })
	}
	withReorderedKeyring := func(t *testing.T) []byte {
		t.Helper()
		var keyring map[string]any
		if err := json.Unmarshal(valid.Keyring, &keyring); err != nil {
			t.Fatal(err)
		}
		wrapped, err := json.Marshal(keyring)
		if err != nil {
			t.Fatal(err)
		}
		return mutate(t, func(root *storeRootFile) { root.Keyring = wrapped })
	}
	tests := []struct {
		name string
		data func(*testing.T) []byte
	}{
		{name: "trailing whitespace", data: func(*testing.T) []byte { return append(bytes.Clone(encoded), '\n') }},
		{name: "outer unknown field", data: withUnknown},
		{name: "outer noncanonical order", data: withReorderedOuter},
		{name: "missing MAC", data: func(t *testing.T) []byte { return mutate(t, func(root *storeRootFile) { root.SelectionMAC = "" }) }},
		{name: "wrong schema", data: func(t *testing.T) []byte {
			return mutate(t, func(root *storeRootFile) { root.Schema = "aplane.store-root.v2" })
		}},
		{name: "wrong format", data: func(t *testing.T) []byte { return mutate(t, func(root *storeRootFile) { root.FormatVersion++ }) }},
		{name: "wrong generation", data: func(t *testing.T) []byte {
			return mutate(t, func(root *storeRootFile) { root.CurrentGenerationID = testStoreRootGenerationB })
		}},
		{name: "wrong term", data: func(t *testing.T) []byte { return mutate(t, func(root *storeRootFile) { root.SelectionTerm++ }) }},
		{name: "keyring schema", data: func(t *testing.T) []byte { return withBadKeyringHeader(t, "schema", "aplane.keyring.v2") }},
		{name: "keyring version", data: func(t *testing.T) []byte {
			return withBadKeyringHeader(t, "envelope_version", float64(2))
		}},
		{name: "keyring KDF", data: func(t *testing.T) []byte { return withBadKeyringHeader(t, "kdf_memory", float64(argon2Memory+1)) }},
		{name: "keyring unknown field", data: func(t *testing.T) []byte { return withBadKeyringHeader(t, "unexpected", true) }},
		{name: "keyring noncanonical order", data: withReorderedKeyring},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := OpenStoreRoot(test.data(t), []byte("passphrase")); err == nil {
				t.Fatal("OpenStoreRoot accepted malformed or unauthenticated input")
			}
		})
	}
	oversized := bytes.Repeat([]byte{'x'}, maxStoreRootBytes+1)
	if _, _, err := OpenStoreRoot(oversized, []byte("passphrase")); err == nil ||
		!strings.Contains(err.Error(), "size limit") {
		t.Fatalf("OpenStoreRoot(oversized) error = %v", err)
	}
}

func TestStoreRootLayoutGateRejectsLegacyAndNonRegularRoots(t *testing.T) {
	passphrase := []byte("passphrase")
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	root, err := SealStoreRoot(kr, passphrase, testStoreRootGenerationA)
	if err != nil {
		t.Fatal(err)
	}
	storeDir := t.TempDir()
	if err := writeStoreRootMarker(storeDir); err != nil {
		t.Fatal(err)
	}
	if err := fsutil.WriteFileDurable(filepath.Join(storeDir, storepaths.StoreRootName), root); err != nil {
		t.Fatal(err)
	}
	opened, selection, err := OpenStoreRootStore(storeDir, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	opened.Zero()
	if selection.CurrentGenerationID != testStoreRootGenerationA {
		t.Fatalf("selection = %+v", selection)
	}

	legacyMarker, err := json.Marshal(storeRootMarker{
		Version: 5,
		Layout:  "keyring/v2",
		Created: "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(storeDir, keystoreMetaFile), legacyMarker, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStoreRootExact(storeDir); err == nil ||
		!strings.Contains(err.Error(), "restore credentials into a freshly initialized store") {
		t.Fatalf("ReadStoreRootExact(legacy marker) error = %v", err)
	}

	symlinkStore := t.TempDir()
	if err := writeStoreRootMarker(symlinkStore); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(symlinkStore, "elsewhere")
	if err := os.WriteFile(target, root, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(symlinkStore, storepaths.StoreRootName)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStoreRootExact(symlinkStore); err == nil {
		t.Fatal("ReadStoreRootExact followed a symlink root")
	}
}
