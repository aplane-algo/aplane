// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
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
		{name: "keyring KDF below floor", data: func(t *testing.T) []byte { return withBadKeyringHeader(t, "kdf_memory", float64(argon2MinMemory-1)) }},
		{name: "keyring KDF above ceiling", data: func(t *testing.T) []byte { return withBadKeyringHeader(t, "kdf_memory", float64(argon2MaxMemory+1)) }},
		{name: "keyring unknown field", data: func(t *testing.T) []byte { return withBadKeyringHeader(t, "unexpected", true) }},
		{name: "keyring noncanonical order", data: withReorderedKeyring},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := OpenStoreRoot(test.data(t), []byte("passphrase"))
			if err == nil {
				t.Fatal("OpenStoreRoot accepted malformed or unauthenticated input")
			}
			if errors.Is(err, ErrInvalidPassphrase) {
				t.Fatalf("OpenStoreRoot() error = %v, reported as a wrong passphrase", err)
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

// Only a passphrase that does not open the sealed keyring is
// ErrInvalidPassphrase. A root that cannot be read, parsed or authenticated
// under the right passphrase is a damaged store, which callers must not
// report as a wrong passphrase.
func TestStoreRootReportsOnlyAPassphraseFailureAsInvalidPassphrase(t *testing.T) {
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
	var file storeRootFile
	if err := json.Unmarshal(root, &file); err != nil {
		t.Fatal(err)
	}
	storeWith := func(t *testing.T, data []byte) string {
		t.Helper()
		dir := t.TempDir()
		if err := writeStoreRootMarker(dir); err != nil {
			t.Fatal(err)
		}
		if data != nil {
			if err := os.WriteFile(filepath.Join(dir, storepaths.StoreRootName), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	reselected := func(t *testing.T, fn func(*storeRootFile)) []byte {
		t.Helper()
		candidate := file
		fn(&candidate)
		data, err := json.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	valid := storeWith(t, root)
	if err := VerifyPassphraseWithStoreRoot(passphrase, valid); err != nil {
		t.Fatalf("VerifyPassphraseWithStoreRoot(right) error = %v", err)
	}
	for name, wrong := range map[string][]byte{"wrong": []byte("wrong passphrase"), "empty": nil} {
		if err := VerifyPassphraseWithStoreRoot(wrong, valid); !errors.Is(err, ErrInvalidPassphrase) {
			t.Fatalf("VerifyPassphraseWithStoreRoot(%s) error = %v, want ErrInvalidPassphrase", name, err)
		}
	}

	damaged := map[string]string{
		"missing root":    storeWith(t, nil),
		"unparsable root": storeWith(t, []byte("{}")),
		"selection MAC": storeWith(t, reselected(t, func(f *storeRootFile) {
			f.CurrentGenerationID = testStoreRootGenerationB
		})),
		"selection term": storeWith(t, reselected(t, func(f *storeRootFile) { f.SelectionTerm++ })),
	}
	if os.Geteuid() != 0 {
		unreadable := storeWith(t, root)
		if err := os.Chmod(filepath.Join(unreadable, storepaths.StoreRootName), 0); err != nil {
			t.Fatal(err)
		}
		damaged["unreadable root"] = unreadable
	}
	for name, dir := range damaged {
		err := VerifyPassphraseWithStoreRoot(passphrase, dir)
		if err == nil {
			t.Fatalf("VerifyPassphraseWithStoreRoot(%s) accepted a damaged store", name)
		}
		if errors.Is(err, ErrInvalidPassphrase) {
			t.Fatalf("VerifyPassphraseWithStoreRoot(%s) error = %v, reported as a wrong passphrase", name, err)
		}
	}
}

// An authenticated selection refuses a root whose selection does not bind to
// the keyring, naming the check that refused it: the term must be the
// keyring's current term, and the MAC must match exactly.
func TestStoreRootSelectionRefusals(t *testing.T) {
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	root, err := SealStoreRoot(kr, []byte("passphrase"), testStoreRootGenerationA)
	if err != nil {
		t.Fatal(err)
	}
	if selection, err := AuthenticateStoreRoot(root, kr); err != nil || selection.CurrentGenerationID != testStoreRootGenerationA {
		t.Fatalf("AuthenticateStoreRoot() = %+v, %v", selection, err)
	}
	mutate := func(edit func(*storeRootFile)) []byte {
		t.Helper()
		file, err := parseStoreRoot(root)
		if err != nil {
			t.Fatal(err)
		}
		edit(&file)
		encoded, err := json.Marshal(file)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	unrelated, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer unrelated.Zero()
	const macFailed = "store root selection MAC verification failed"
	tests := []struct {
		name string
		root []byte
		kr   *Keyring
		want string
	}{
		{"another generation", mutate(func(f *storeRootFile) { f.CurrentGenerationID = testStoreRootGenerationB }), kr, macFailed},
		{"an edited MAC", mutate(func(f *storeRootFile) {
			last := "0"
			if strings.HasSuffix(f.SelectionMAC, "0") {
				last = "1"
			}
			f.SelectionMAC = f.SelectionMAC[:len(f.SelectionMAC)-1] + last
		}), kr, macFailed},
		{"another keyring", root, unrelated, macFailed},
		{"another term", mutate(func(f *storeRootFile) { f.SelectionTerm++ }), kr, fmt.Sprintf(
			"store root selection term %d does not equal keyring current term %d", kr.CurrentTerm()+1, kr.CurrentTerm(),
		)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := AuthenticateStoreRoot(tt.root, tt.kr); err == nil || err.Error() != tt.want {
				t.Fatalf("AuthenticateStoreRoot() error = %v, want %q", err, tt.want)
			}
			if _, err := ReselectStoreRoot(tt.root, tt.kr, testStoreRootGenerationB); err == nil || err.Error() != tt.want {
				t.Fatalf("ReselectStoreRoot() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func sealStoreRootWithKDFForTest(t *testing.T, kr *Keyring, passphrase []byte, generationID string, kdfTime, kdfMemory uint32, kdfThreads uint8) []byte {
	t.Helper()
	salt, err := randomBytes(masterSaltLen)
	if err != nil {
		t.Fatalf("randomBytes(salt) error = %v", err)
	}
	payload := storeRootKeyringPayload{
		Schema:            StoreRootKeyringSchema,
		CurrentTerm:       kr.currentTerm,
		Terms:             sealedTermsFromKeyring(kr),
		HistoricalAnchors: slices.Clone(kr.historicalAnchors),
	}
	if payload.HistoricalAnchors == nil {
		payload.HistoricalAnchors = []HistoricalGenerationAnchor{}
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal(payload) error = %v", err)
	}
	defer ZeroBytes(plaintext)

	kek := deriveMasterKeyParams(passphrase, salt, kdfTime, kdfMemory, kdfThreads)
	defer ZeroBytes(kek)
	gcm, err := newGCM(kek)
	if err != nil {
		t.Fatalf("newGCM() error = %v", err)
	}
	nonce, err := randomBytes(gcm.NonceSize())
	if err != nil {
		t.Fatalf("randomBytes(nonce) error = %v", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, storeRootKeyringHeaderAAD(
		StoreRootKeyringSchema,
		StoreRootKeyringEnvelopeVersion,
		kdfTime,
		kdfMemory,
		kdfThreads,
		salt,
		nonce,
	))
	wrapped, err := json.Marshal(keyringFile{
		Schema:        StoreRootKeyringSchema,
		EnvelopeVer:   StoreRootKeyringEnvelopeVersion,
		KDFTime:       kdfTime,
		KDFMemory:     kdfMemory,
		KDFThreads:    kdfThreads,
		Salt:          base64.StdEncoding.EncodeToString(salt),
		Nonce:         base64.StdEncoding.EncodeToString(nonce),
		SealedKeyring: base64.StdEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		t.Fatalf("Marshal(keyringFile) error = %v", err)
	}
	root, err := encodeStoreRoot(kr, wrapped, generationID)
	if err != nil {
		t.Fatalf("encodeStoreRoot() error = %v", err)
	}
	return root
}

func TestStoreRootKeyringHeaderAADIncludesAllFields(t *testing.T) {
	salt := bytes.Repeat([]byte{0x11}, masterSaltLen)
	nonce := bytes.Repeat([]byte{0x22}, gcmNonceBytes)
	base := storeRootKeyringHeaderAAD(StoreRootKeyringSchema, StoreRootKeyringEnvelopeVersion, 2, 65536, 4, salt, nonce)

	variants := []struct {
		name string
		aad  []byte
	}{
		{"schema", storeRootKeyringHeaderAAD("aplane.keyring.v4", StoreRootKeyringEnvelopeVersion, 2, 65536, 4, salt, nonce)},
		{"version", storeRootKeyringHeaderAAD(StoreRootKeyringSchema, StoreRootKeyringEnvelopeVersion+1, 2, 65536, 4, salt, nonce)},
		{"kdf_time", storeRootKeyringHeaderAAD(StoreRootKeyringSchema, StoreRootKeyringEnvelopeVersion, 3, 65536, 4, salt, nonce)},
		{"kdf_memory", storeRootKeyringHeaderAAD(StoreRootKeyringSchema, StoreRootKeyringEnvelopeVersion, 2, 65537, 4, salt, nonce)},
		{"kdf_threads", storeRootKeyringHeaderAAD(StoreRootKeyringSchema, StoreRootKeyringEnvelopeVersion, 2, 65536, 5, salt, nonce)},
		{"salt", storeRootKeyringHeaderAAD(StoreRootKeyringSchema, StoreRootKeyringEnvelopeVersion, 2, 65536, 4, bytes.Repeat([]byte{0x33}, masterSaltLen), nonce)},
		{"nonce", storeRootKeyringHeaderAAD(StoreRootKeyringSchema, StoreRootKeyringEnvelopeVersion, 2, 65536, 4, salt, bytes.Repeat([]byte{0x44}, gcmNonceBytes))},
	}
	for _, tc := range variants {
		if bytes.Equal(base, tc.aad) {
			t.Fatalf("storeRootKeyringHeaderAAD did not change when %s changed", tc.name)
		}
	}
}

func TestStoreRootRejectsOutOfRangeKDFParamsBeforeDerivation(t *testing.T) {
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
	var validKF keyringFile
	if err := json.Unmarshal(valid.Keyring, &validKF); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		mutate  func(*keyringFile)
		wantErr string
	}{
		{"time zero", func(k *keyringFile) { k.KDFTime = 0 }, "keyring kdf_time 0 is outside supported range"},
		{"time below floor", func(k *keyringFile) { k.KDFTime = argon2MinTime - 1 }, "keyring kdf_time 1 is outside supported range"},
		{"time above ceiling", func(k *keyringFile) { k.KDFTime = argon2MaxTime + 1 }, "keyring kdf_time 5 is outside supported range"},
		{"time max uint32", func(k *keyringFile) { k.KDFTime = math.MaxUint32 }, "keyring kdf_time 4294967295 is outside supported range"},
		{"memory zero", func(k *keyringFile) { k.KDFMemory = 0 }, "keyring kdf_memory 0 is outside supported range"},
		{"memory below floor", func(k *keyringFile) { k.KDFMemory = argon2MinMemory - 1 }, "keyring kdf_memory 65535 is outside supported range"},
		{"memory above ceiling", func(k *keyringFile) { k.KDFMemory = argon2MaxMemory + 1 }, "keyring kdf_memory 262145 is outside supported range"},
		{"memory max uint32", func(k *keyringFile) { k.KDFMemory = math.MaxUint32 }, "keyring kdf_memory 4294967295 is outside supported range"},
		{"threads zero", func(k *keyringFile) { k.KDFThreads = 0 }, "keyring kdf_threads 0 is not supported"},
		{"threads below fixed", func(k *keyringFile) { k.KDFThreads = argon2AcceptedThreads - 1 }, "keyring kdf_threads 3 is not supported"},
		{"threads above fixed", func(k *keyringFile) { k.KDFThreads = argon2AcceptedThreads + 1 }, "keyring kdf_threads 5 is not supported"},
		{"threads max uint8", func(k *keyringFile) { k.KDFThreads = math.MaxUint8 }, "keyring kdf_threads 255 is not supported"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kdfDeriveHook = func(tm, mem uint32, thr uint8) {
				t.Fatalf("Argon2id ran with (%d, %d, %d) despite out-of-range keyring KDF parameters", tm, mem, thr)
			}
			defer func() { kdfDeriveHook = nil }()

			kf := validKF
			tc.mutate(&kf)
			wrapped, err := json.Marshal(kf)
			if err != nil {
				t.Fatal(err)
			}
			// Recompute a valid selection MAC so only the KDF range gate
			// rejects the root on OpenStoreRoot, AuthenticateStoreRoot, and
			// ReselectStoreRoot.
			candidate, err := encodeStoreRoot(kr, wrapped, testStoreRootGenerationA)
			if err != nil {
				t.Fatal(err)
			}

			_, _, err = OpenStoreRoot(candidate, []byte("passphrase"))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("OpenStoreRoot() error = %v, want substring %q", err, tc.wantErr)
			}
			if errors.Is(err, ErrInvalidPassphrase) {
				t.Fatalf("OpenStoreRoot() reported out-of-range KDF as ErrInvalidPassphrase: %v", err)
			}
			if _, err := AuthenticateStoreRoot(candidate, kr); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("AuthenticateStoreRoot() error = %v, want substring %q", err, tc.wantErr)
			}
			if _, err := ReselectStoreRoot(candidate, kr, testStoreRootGenerationB); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ReselectStoreRoot() error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestStoreRootDerivesFromStoredInRangeKDFParams(t *testing.T) {
	passphrase := []byte("stored-root-kdf-passphrase")

	// Exact ceiling bounds are covered without heavy allocations in
	// TestCheckKDFParamsBounds; here we exercise real derivation at the
	// literal historical floor (2, 65536, 4) and a non-default in-range tuple.
	cases := []struct {
		name    string
		time    uint32
		memory  uint32
		threads uint8
	}{
		{"literal floor", 2, 65536, 4},
		{"mid-range non-default", 3, 68 * 1024, 4},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kr, err := NewKeyring()
			if err != nil {
				t.Fatal(err)
			}
			defer kr.Zero()
			sealed := sealStoreRootWithKDFForTest(t, kr, passphrase, testStoreRootGenerationA, tc.time, tc.memory, tc.threads)

			var gotTime, gotMemory uint32
			var gotThreads uint8
			calls := 0
			kdfDeriveHook = func(tm, mem uint32, thr uint8) {
				calls++
				gotTime, gotMemory, gotThreads = tm, mem, thr
			}
			defer func() { kdfDeriveHook = nil }()

			opened, selection, err := OpenStoreRoot(sealed, passphrase)
			if err != nil {
				t.Fatalf("OpenStoreRoot() error = %v", err)
			}
			defer opened.Zero()
			if selection.CurrentGenerationID != testStoreRootGenerationA || opened.CurrentTerm() != kr.CurrentTerm() {
				t.Fatalf("selection = %+v term = %d", selection, opened.CurrentTerm())
			}
			if calls != 1 || gotTime != tc.time || gotMemory != tc.memory || gotThreads != tc.threads {
				t.Fatalf("derived with (%d, %d, %d) x%d, want (%d, %d, %d) x1",
					gotTime, gotMemory, gotThreads, calls, tc.time, tc.memory, tc.threads)
			}

			// AuthenticateStoreRoot and ReselectStoreRoot must accept and
			// preserve the non-default wrapped keyring bytes untouched.
			if sel, err := AuthenticateStoreRoot(sealed, opened); err != nil || sel.CurrentGenerationID != testStoreRootGenerationA {
				t.Fatalf("AuthenticateStoreRoot() = %+v, %v", sel, err)
			}
			reselected, err := ReselectStoreRoot(sealed, opened, testStoreRootGenerationB)
			if err != nil {
				t.Fatalf("ReselectStoreRoot() error = %v", err)
			}
			reopened, sel2, err := OpenStoreRoot(reselected, passphrase)
			if err != nil {
				t.Fatalf("OpenStoreRoot(reselected) error = %v", err)
			}
			defer reopened.Zero()
			if sel2.CurrentGenerationID != testStoreRootGenerationB {
				t.Fatalf("reselected generation = %q, want %q", sel2.CurrentGenerationID, testStoreRootGenerationB)
			}
			if calls != 2 || gotTime != tc.time || gotMemory != tc.memory || gotThreads != tc.threads {
				t.Fatalf("reopen derived with (%d, %d, %d) x%d, want (%d, %d, %d) x2",
					gotTime, gotMemory, gotThreads, calls, tc.time, tc.memory, tc.threads)
			}
		})
	}

	// Tampering an in-range KDF parameter after sealing fails AEAD unwrap
	// (KEK and header AAD both bind the stored parameters).
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	sealed, err := SealStoreRoot(kr, passphrase, testStoreRootGenerationA)
	if err != nil {
		t.Fatal(err)
	}
	var root storeRootFile
	if err := json.Unmarshal(sealed, &root); err != nil {
		t.Fatal(err)
	}
	var kf keyringFile
	if err := json.Unmarshal(root.Keyring, &kf); err != nil {
		t.Fatal(err)
	}
	kf.KDFMemory++
	wrapped, err := json.Marshal(kf)
	if err != nil {
		t.Fatal(err)
	}
	tampered, err := encodeStoreRoot(kr, wrapped, testStoreRootGenerationA)
	if err != nil {
		t.Fatal(err)
	}
	var gotMemory uint32
	kdfDeriveHook = func(_, mem uint32, _ uint8) { gotMemory = mem }
	defer func() { kdfDeriveHook = nil }()
	if _, _, err := OpenStoreRoot(tampered, passphrase); !errors.Is(err, ErrInvalidPassphrase) {
		t.Fatalf("OpenStoreRoot(in-range tampered KDF) error = %v, want ErrInvalidPassphrase", err)
	}
	if gotMemory != argon2Memory+1 {
		t.Fatalf("derived memory = %d, want %d", gotMemory, argon2Memory+1)
	}
}
