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
)

func newTestKeyring(t *testing.T) *Keyring {
	t.Helper()
	kr, err := NewKeyring()
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	t.Cleanup(kr.Zero)
	return kr
}

func TestKeyringSealOpenRoundTrip(t *testing.T) {
	kr := newTestKeyring(t)
	ctx := AccountKeyContext("ADDR")
	plaintext := []byte(`{"kind":"key"}`)

	sealed, err := kr.Seal(plaintext, ctx)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	opened, err := kr.Open(sealed, ctx)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("Open() = %q, want %q", opened, plaintext)
	}
}

// TestKeyringOpenRejectsMismatchedContext is the reason the AAD carries the
// object's logical identity: an envelope must not be openable as a different
// object, even with the right key.
func TestKeyringOpenRejectsMismatchedContext(t *testing.T) {
	kr := newTestKeyring(t)
	sealed, err := kr.Seal([]byte("secret"), AccountKeyContext("ADDR-ONE"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	cases := []struct {
		name string
		ctx  ObjectContext
	}{
		{"different selector", AccountKeyContext("ADDR-TWO")},
		{"different class, same selector", SentryCredentialContext("ADDR-ONE")},
		{"template class", KeyTypeTemplateContext("ADDR-ONE")},
		{"recovered batch class", RecoveredBatchContext("ADDR-ONE")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := kr.Open(sealed, tc.ctx); err == nil {
				t.Fatalf("Open() with %s accepted an envelope sealed for a different object", tc.ctx)
			}
		})
	}
}

// TestKeyringOpenRejectsEditedTerm proves the term is bound, not merely
// recorded: editing the header cannot redirect an envelope to another term.
func TestKeyringOpenRejectsEditedTerm(t *testing.T) {
	kr := newTestKeyring(t)
	ctx := KeyTypeTemplateContext("example-v1")
	sealed, err := kr.Seal([]byte("template"), ctx)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	var envelope map[string]any
	if err := json.Unmarshal(sealed, &envelope); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if envelope["term"].(float64) != float64(FirstTerm) {
		t.Fatalf("term = %v, want %d", envelope["term"], FirstTerm)
	}
	envelope["term"] = float64(FirstTerm + 1)
	edited, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// The keyring holds no such term, so this fails on lookup; the AAD
	// binding is what stops it if a later term ever exists.
	if _, err := kr.Open(edited, ctx); err == nil {
		t.Fatal("Open() accepted an envelope whose term was edited")
	}
}

// TestKeyringOpenRejectsForeignTermKey proves AAD binding catches an edited
// term even when the keyring does hold that term's key.
func TestKeyringOpenRejectsForeignTermKey(t *testing.T) {
	kr := newTestKeyring(t)
	ctx := AccountKeyContext("ADDR")
	sealed, err := kr.Seal([]byte("secret"), ctx)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	// Give the keyring a second term whose key is the same bytes as term 1.
	// Editing the header to name term 2 then passes key lookup and must
	// still fail authentication, because the term is in the AAD.
	kr.terms[FirstTerm+1] = append([]byte(nil), kr.terms[FirstTerm]...)

	var envelope map[string]any
	if err := json.Unmarshal(sealed, &envelope); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	envelope["term"] = float64(FirstTerm + 1)
	edited, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if _, err := kr.Open(edited, ctx); err == nil {
		t.Fatal("Open() accepted an edited term whose key was present: the term is not bound")
	}
}

func TestObjectContextValidation(t *testing.T) {
	kr := newTestKeyring(t)
	cases := []struct {
		name string
		ctx  ObjectContext
	}{
		{"empty class", ObjectContext{Selector: "s"}},
		{"unknown class", ObjectContext{Class: "invented", Selector: "s"}},
		{"empty selector", ObjectContext{Class: ClassAccountKey}},
		{"NUL in selector", ObjectContext{Class: ClassAccountKey, Selector: "a\x00b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := kr.Seal([]byte("x"), tc.ctx); err == nil {
				t.Fatal("Seal() accepted an invalid object context")
			}
		})
	}
}

// TestAADFieldsAreUnambiguous proves the length-prefixed encoding cannot be
// confused: no rearrangement of class and selector produces the same AAD.
func TestAADFieldsAreUnambiguous(t *testing.T) {
	a := aadFor(1, ObjectContext{Class: "ab", Selector: "c"})
	b := aadFor(1, ObjectContext{Class: "a", Selector: "bc"})
	if bytes.Equal(a, b) {
		t.Fatal("AAD is ambiguous across a class/selector boundary")
	}
	if bytes.Equal(aadFor(1, AccountKeyContext("X")), aadFor(2, AccountKeyContext("X"))) {
		t.Fatal("AAD does not distinguish terms")
	}
}

// ----------------------------------------------------------------------------
// keyring.enc

func TestKeyringFileRoundTrip(t *testing.T) {
	kr := newTestKeyring(t)
	passphrase := []byte("store-passphrase")
	ctx := AccountKeyContext("ADDR")
	sealedData, err := kr.Seal([]byte("secret"), ctx)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	encoded, err := SealKeyring(kr, passphrase)
	if err != nil {
		t.Fatalf("SealKeyring() error = %v", err)
	}
	reopened, err := OpenKeyring(encoded, passphrase)
	if err != nil {
		t.Fatalf("OpenKeyring() error = %v", err)
	}
	defer reopened.Zero()

	if reopened.CurrentTerm() != FirstTerm {
		t.Fatalf("CurrentTerm() = %d, want %d", reopened.CurrentTerm(), FirstTerm)
	}
	opened, err := reopened.Open(sealedData, ctx)
	if err != nil {
		t.Fatalf("data sealed before the round trip does not open after it: %v", err)
	}
	if string(opened) != "secret" {
		t.Fatalf("Open() = %q, want secret", opened)
	}
}

// TestOpenKeyringRejectsWrongPassphrase pins that the unwrap IS the
// passphrase check — there is no separate verifier to consult.
func TestOpenKeyringRejectsWrongPassphrase(t *testing.T) {
	kr := newTestKeyring(t)
	encoded, err := SealKeyring(kr, []byte("right-passphrase"))
	if err != nil {
		t.Fatalf("SealKeyring() error = %v", err)
	}
	if _, err := OpenKeyring(encoded, []byte("wrong-passphrase")); err == nil {
		t.Fatal("OpenKeyring() accepted a wrong passphrase")
	}
}

// TestKeyringFileIsSelfContained proves the root carries its own KDF
// parameters and salt, so nothing else has to agree with it and a passphrase
// change is one file write.
func TestKeyringFileIsSelfContained(t *testing.T) {
	kr := newTestKeyring(t)
	encoded, err := SealKeyring(kr, []byte("passphrase"))
	if err != nil {
		t.Fatalf("SealKeyring() error = %v", err)
	}
	var file map[string]any
	if err := json.Unmarshal(encoded, &file); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	for _, field := range []string{"kdf_time", "kdf_memory", "kdf_threads", "salt", "nonce", "sealed_keyring"} {
		if _, ok := file[field]; !ok {
			t.Fatalf("keyring file is missing %q: %v", field, file)
		}
	}
	// No plaintext key material escapes into the file.
	if strings.Contains(string(encoded), "current_term") {
		t.Fatal("keyring payload leaked outside the sealed ciphertext")
	}
}

func TestOpenKeyringRejectsTamperedCiphertext(t *testing.T) {
	kr := newTestKeyring(t)
	passphrase := []byte("passphrase")
	encoded, err := SealKeyring(kr, passphrase)
	if err != nil {
		t.Fatalf("SealKeyring() error = %v", err)
	}
	var file map[string]any
	if err := json.Unmarshal(encoded, &file); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	sealed := file["sealed_keyring"].(string)
	// Flip one base64 character to a different valid one.
	swapped := "A"
	if strings.HasPrefix(sealed, "A") {
		swapped = "B"
	}
	file["sealed_keyring"] = swapped + sealed[1:]
	tampered, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if _, err := OpenKeyring(tampered, passphrase); err == nil {
		t.Fatal("OpenKeyring() accepted tampered ciphertext")
	}
}

func TestKeyringZeroClearsTermKeys(t *testing.T) {
	kr, err := NewKeyring()
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	key := kr.terms[FirstTerm]
	kr.Zero()
	for i, b := range key {
		if b != 0 {
			t.Fatalf("term key byte %d = %d after Zero(), want 0", i, b)
		}
	}
	if _, err := kr.Seal([]byte("x"), AccountKeyContext("ADDR")); err == nil {
		t.Fatal("Seal() worked on a zeroed keyring")
	}
}

func TestNewKeyringFromKeyCopiesInput(t *testing.T) {
	source := bytes.Repeat([]byte{7}, argon2KeyLen)
	kr, err := NewKeyringFromKey(source)
	if err != nil {
		t.Fatalf("NewKeyringFromKey() error = %v", err)
	}
	defer kr.Zero()
	ZeroBytes(source)
	// The keyring must own its copy: zeroing the caller's buffer must not
	// disturb it.
	if _, err := kr.Seal([]byte("x"), AccountKeyContext("ADDR")); err != nil {
		t.Fatalf("Seal() error = %v after the caller zeroed its input", err)
	}
}

// ----------------------------------------------------------------------------
// keyring store

func TestCreateAndOpenKeyringStore(t *testing.T) {
	dir := t.TempDir()
	passphrase := []byte("store-passphrase")

	created, err := CreateKeyringStore(dir, passphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	ctx := AccountKeyContext("ADDR")
	sealed, err := created.Seal([]byte("secret"), ctx)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	created.Zero()

	if !KeyringExistsIn(dir) {
		t.Fatal("KeyringExistsIn() = false after CreateKeyringStore")
	}
	opened, err := OpenKeyringStore(dir, passphrase)
	if err != nil {
		t.Fatalf("OpenKeyringStore() error = %v", err)
	}
	defer opened.Zero()
	plain, err := opened.Open(sealed, ctx)
	if err != nil || string(plain) != "secret" {
		t.Fatalf("Open() = %q, %v", plain, err)
	}
}

func TestOpenKeyringStoreRejectsWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	kr, err := CreateKeyringStore(dir, []byte("right"))
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	kr.Zero()
	if _, err := OpenKeyringStore(dir, []byte("wrong")); err == nil {
		t.Fatal("OpenKeyringStore() accepted a wrong passphrase")
	}
	if err := VerifyPassphraseWithKeyring([]byte("right"), dir); err != nil {
		t.Fatalf("VerifyPassphraseWithKeyring(correct) error = %v", err)
	}
	if err := VerifyPassphraseWithKeyring([]byte("wrong"), dir); err == nil {
		t.Fatal("VerifyPassphraseWithKeyring accepted a wrong passphrase")
	}
}

// TestKeyringMarkerCarriesNoSecrets pins that the version gate is inert: all
// key material and KDF state live in the root, so the marker cannot disagree
// with it.
func TestKeyringMarkerCarriesNoSecrets(t *testing.T) {
	dir := t.TempDir()
	kr, err := CreateKeyringStore(dir, []byte("passphrase"))
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	kr.Zero()

	data, err := os.ReadFile(filepath.Join(dir, keystoreMetaFile))
	if err != nil {
		t.Fatalf("ReadFile(marker) error = %v", err)
	}
	var marker map[string]any
	if err := json.Unmarshal(data, &marker); err != nil {
		t.Fatalf("Unmarshal(marker) error = %v", err)
	}
	if marker["version"] != float64(KeyringKeystoreMetadataVersion) ||
		marker["layout"] != KeystoreLayoutKeyringV1 {
		t.Fatalf("marker = %v, want version %d layout %q",
			marker, KeyringKeystoreMetadataVersion, KeystoreLayoutKeyringV1)
	}
	for _, forbidden := range []string{"salt", "check", "kdf_time", "kdf_memory", "kdf_threads"} {
		if _, present := marker[forbidden]; present {
			t.Fatalf("marker carries %q; secrets and KDF state belong in the root: %v", forbidden, marker)
		}
	}
}

func TestOpenKeyringStoreRejectsOtherVersions(t *testing.T) {
	dir := t.TempDir()
	kr, err := CreateKeyringStore(dir, []byte("passphrase"))
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	kr.Zero()

	markerPath := filepath.Join(dir, keystoreMetaFile)
	for _, tc := range []struct {
		name    string
		marker  string
		wantErr string
	}{
		{"older version", `{"version":3,"layout":"generations/v1"}`, "only reads stores it initialized"},
		{"unknown layout", `{"version":4,"layout":"invented/v9"}`, "unsupported layout"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(markerPath, []byte(tc.marker), 0o600); err != nil {
				t.Fatalf("WriteFile(marker) error = %v", err)
			}
			_, err := OpenKeyringStore(dir, []byte("passphrase"))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("OpenKeyringStore() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestCreateKeyringStoreRefusesExisting(t *testing.T) {
	dir := t.TempDir()
	kr, err := CreateKeyringStore(dir, []byte("passphrase"))
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	kr.Zero()
	if _, err := CreateKeyringStore(dir, []byte("passphrase")); err == nil {
		t.Fatal("CreateKeyringStore() overwrote an existing keyring")
	}
}

// TestWriteKeyringIsPassphraseChange pins that changing the passphrase is one
// file write: the same terms, resealed, with nothing else to update.
func TestWriteKeyringIsPassphraseChange(t *testing.T) {
	dir := t.TempDir()
	old, err := CreateKeyringStore(dir, []byte("old-passphrase"))
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	ctx := KeyTypeTemplateContext("example-v1")
	sealed, err := old.Seal([]byte("template"), ctx)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if err := WriteKeyring(dir, old, []byte("new-passphrase")); err != nil {
		t.Fatalf("WriteKeyring() error = %v", err)
	}
	old.Zero()

	if _, err := OpenKeyringStore(dir, []byte("old-passphrase")); err == nil {
		t.Fatal("the old passphrase still opens the store after a passphrase change")
	}
	reopened, err := OpenKeyringStore(dir, []byte("new-passphrase"))
	if err != nil {
		t.Fatalf("OpenKeyringStore(new) error = %v", err)
	}
	defer reopened.Zero()
	// Data is untouched by a passphrase change: same terms, new wrapping.
	if plain, err := reopened.Open(sealed, ctx); err != nil || string(plain) != "template" {
		t.Fatalf("Open() = %q, %v; data should survive a passphrase change unchanged", plain, err)
	}
}

// TestOpenKeyringRejectsEditedHeader pins that no edit to the root file's
// plaintext header yields a readable keyring.
//
// Each field here is rejected by a mechanism that predates the header
// binding: schema and envelope_version by OpenKeyring's equality checks, the
// KDF parameters and salt because they feed the KEK, and the nonce because it
// feeds the keystream. The binding in keyringHeaderAAD is a backstop for that
// coverage, not its source — neutering it does not make this test fail. Its
// value is that the property stops depending on those checks staying in
// place, which is the same reason the term envelope binds its own header.
func TestOpenKeyringRejectsEditedHeader(t *testing.T) {
	passphrase := []byte("keyring-header-binding")
	kr, err := NewKeyring()
	if err != nil {
		t.Fatalf("NewKeyring(): %v", err)
	}
	defer kr.Zero()
	sealed, err := SealKeyring(kr, passphrase)
	if err != nil {
		t.Fatalf("SealKeyring(): %v", err)
	}

	edits := map[string]func(map[string]any){
		"schema":           func(m map[string]any) { m["schema"] = "aplane.keyring.v2" },
		"envelope_version": func(m map[string]any) { m["envelope_version"] = 2 },
		"kdf_time":         func(m map[string]any) { m["kdf_time"] = 3 },
		"kdf_memory":       func(m map[string]any) { m["kdf_memory"] = 32768 },
		"kdf_threads":      func(m map[string]any) { m["kdf_threads"] = 2 },
	}
	for field, edit := range edits {
		t.Run(field, func(t *testing.T) {
			var file map[string]any
			if err := json.Unmarshal(sealed, &file); err != nil {
				t.Fatalf("Unmarshal(): %v", err)
			}
			edit(file)
			edited, err := json.Marshal(file)
			if err != nil {
				t.Fatalf("Marshal(): %v", err)
			}
			opened, err := OpenKeyring(edited, passphrase)
			if err == nil {
				opened.Zero()
				t.Fatalf("OpenKeyring() accepted an edited %s", field)
			}
		})
	}

	// The unedited file still opens, so the rejections above are the edits
	// and not a broken seal.
	reopened, err := OpenKeyring(sealed, passphrase)
	if err != nil {
		t.Fatalf("OpenKeyring(unedited): %v", err)
	}
	reopened.Zero()
}

// TestKeyringHeaderAADIsUnambiguous tests the header binding directly, since
// no end-to-end path can isolate it: every header field is already covered by
// a validation check or by the KEK derivation.
//
// What must hold is that the encoding is injective — no two distinct headers
// share an AAD, including headers that differ only in where one field ends
// and the next begins.
func TestKeyringHeaderAADIsUnambiguous(t *testing.T) {
	salt := bytes.Repeat([]byte{0x11}, masterSaltLen)
	nonce := bytes.Repeat([]byte{0x22}, 12)
	base := keyringHeaderAAD(KeyringSchema, KeyringFileVersion, argon2Time, argon2Memory, argon2Threads, salt, nonce)

	variants := map[string][]byte{
		"schema":      keyringHeaderAAD("aplane.keyring.v2", KeyringFileVersion, argon2Time, argon2Memory, argon2Threads, salt, nonce),
		"version":     keyringHeaderAAD(KeyringSchema, KeyringFileVersion+1, argon2Time, argon2Memory, argon2Threads, salt, nonce),
		"kdf time":    keyringHeaderAAD(KeyringSchema, KeyringFileVersion, argon2Time+1, argon2Memory, argon2Threads, salt, nonce),
		"kdf memory":  keyringHeaderAAD(KeyringSchema, KeyringFileVersion, argon2Time, argon2Memory+1, argon2Threads, salt, nonce),
		"kdf threads": keyringHeaderAAD(KeyringSchema, KeyringFileVersion, argon2Time, argon2Memory, argon2Threads+1, salt, nonce),
		"salt":        keyringHeaderAAD(KeyringSchema, KeyringFileVersion, argon2Time, argon2Memory, argon2Threads, bytes.Repeat([]byte{0x33}, masterSaltLen), nonce),
		"nonce":       keyringHeaderAAD(KeyringSchema, KeyringFileVersion, argon2Time, argon2Memory, argon2Threads, salt, bytes.Repeat([]byte{0x44}, 12)),
	}
	for field, variant := range variants {
		if bytes.Equal(base, variant) {
			t.Fatalf("changing %s left the header AAD unchanged", field)
		}
	}

	// Field boundaries: moving a byte from the salt into the nonce must not
	// produce the same AAD, which is what the length prefixes buy.
	shiftedSalt := bytes.Repeat([]byte{0x55}, masterSaltLen+1)
	shiftedNonce := bytes.Repeat([]byte{0x55}, 11)
	longSalt := keyringHeaderAAD(KeyringSchema, KeyringFileVersion, argon2Time, argon2Memory, argon2Threads, shiftedSalt, shiftedNonce)
	evenSplit := keyringHeaderAAD(KeyringSchema, KeyringFileVersion, argon2Time, argon2Memory, argon2Threads, shiftedSalt[:masterSaltLen], bytes.Repeat([]byte{0x55}, 12))
	if bytes.Equal(longSalt, evenSplit) {
		t.Fatal("two different field splits produced the same header AAD")
	}
}

// TestOpenKeyringRejectsExcessiveKDFParameters proves the root cannot ask for
// unbounded work.
//
// The KDF parameters are read before anything authenticates them — the KEK
// has to exist before the AEAD can verify the header — so the header binding
// is no defence here. A damaged or edited root naming a huge memory cost
// would otherwise hang or OOM a daemon that also serves every other identity.
func TestOpenKeyringRejectsExcessiveKDFParameters(t *testing.T) {
	passphrase := []byte("keyring-kdf-ceilings")
	kr, err := NewKeyring()
	if err != nil {
		t.Fatalf("NewKeyring(): %v", err)
	}
	defer kr.Zero()
	sealed, err := SealKeyring(kr, passphrase)
	if err != nil {
		t.Fatalf("SealKeyring(): %v", err)
	}

	cases := map[string]struct {
		field string
		value any
	}{
		"kdf_time above ceiling":    {"kdf_time", maxKDFTime + 1},
		"kdf_memory above ceiling":  {"kdf_memory", maxKDFMemory + 1},
		"kdf_threads above ceiling": {"kdf_threads", maxKDFThreads + 1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var file map[string]any
			if err := json.Unmarshal(sealed, &file); err != nil {
				t.Fatalf("Unmarshal(): %v", err)
			}
			file[tc.field] = tc.value
			edited, err := json.Marshal(file)
			if err != nil {
				t.Fatalf("Marshal(): %v", err)
			}
			opened, err := OpenKeyring(edited, passphrase)
			if err == nil {
				opened.Zero()
				t.Fatalf("OpenKeyring() accepted %s beyond its ceiling", tc.field)
			}
			if !strings.Contains(err.Error(), "exceeds the limit") {
				t.Fatalf("OpenKeyring() error = %v, want a ceiling rejection", err)
			}
		})
	}
}

// TestOpenKeyringRejectsMultipleTerms proves this release enforces its
// single-term format rather than assuming it.
//
// A multi-term root belongs to a release that has retiring terms and the
// authority split that governs them. Reading one here would reauthorize a
// retired term for current state, so the format gate refuses it and phase 3
// has to bump the version to relax that.
func TestOpenKeyringRejectsMultipleTerms(t *testing.T) {
	passphrase := []byte("keyring-single-term")
	kr, err := NewKeyring()
	if err != nil {
		t.Fatalf("NewKeyring(): %v", err)
	}
	defer kr.Zero()

	second, err := randomBytes(argon2KeyLen)
	if err != nil {
		t.Fatalf("randomBytes(): %v", err)
	}
	forged := &Keyring{
		terms:       map[int][]byte{FirstTerm: kr.terms[FirstTerm], FirstTerm + 1: second},
		currentTerm: FirstTerm + 1,
	}
	sealed, err := SealKeyring(forged, passphrase)
	if err != nil {
		t.Fatalf("SealKeyring(): %v", err)
	}
	opened, err := OpenKeyring(sealed, passphrase)
	if err == nil {
		opened.Zero()
		t.Fatal("OpenKeyring() accepted a multi-term root; a phase-1 binary must not read one")
	}
	if !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("OpenKeyring() error = %v, want a single-term rejection", err)
	}
}
