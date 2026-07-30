// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
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

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
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
		{"rotation snapshot class", RotationSnapshotContext()},
		{"rotation baseline class", RotationBaselineContext()},
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
		{"wrong rotation snapshot selector", ObjectContext{Class: ClassRotationSnapshot, Selector: "current"}},
		{"wrong rotation baseline selector", ObjectContext{Class: ClassRotationBaseline, Selector: "pending"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := kr.Seal([]byte("x"), tc.ctx); err == nil {
				t.Fatal("Seal() accepted an invalid object context")
			}
		})
	}
}

func TestInspectTermEnvelopeDistinguishesPlaintextAndMalformedEnvelope(t *testing.T) {
	kr := newTestKeyring(t)
	sealed, err := kr.Seal([]byte("secret"), AccountKeyContext("ADDR"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if term, present, err := InspectTermEnvelope(sealed); err != nil || !present || term != FirstTerm {
		t.Fatalf("InspectTermEnvelope(sealed) = %d, %t, %v", term, present, err)
	}
	if term, present, err := InspectTermEnvelope([]byte(`{"schema":"plaintext.v1"}`)); err != nil ||
		present ||
		term != 0 {
		t.Fatalf("InspectTermEnvelope(plaintext) = %d, %t, %v", term, present, err)
	}
	if _, present, err := InspectTermEnvelope([]byte(`{"envelope_version":2}`)); err == nil || !present {
		t.Fatalf("InspectTermEnvelope(foreign envelope) = present %t, error %v", present, err)
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

func TestNewKeyringFromTermKeyUsesSpecifiedTermAndCopiesInput(t *testing.T) {
	source := bytes.Repeat([]byte{9}, argon2KeyLen)
	kr, err := NewKeyringFromTermKey(2, source)
	if err != nil {
		t.Fatalf("NewKeyringFromTermKey() error = %v", err)
	}
	defer kr.Zero()
	ZeroBytes(source)
	if kr.CurrentTerm() != 2 {
		t.Fatalf("CurrentTerm() = %d, want 2", kr.CurrentTerm())
	}
	sealed, err := kr.Seal([]byte("snapshot"), RotationSnapshotContext())
	if err != nil {
		t.Fatalf("Seal() error = %v after caller input was zeroed", err)
	}
	if term, err := EnvelopeTerm(sealed); err != nil || term != 2 {
		t.Fatalf("EnvelopeTerm() = %d, %v, want 2, nil", term, err)
	}
	if _, err := NewKeyringFromTermKey(0, bytes.Repeat([]byte{1}, argon2KeyLen)); err == nil {
		t.Fatal("NewKeyringFromTermKey() accepted term zero")
	}
}

func TestRotationSnapshotReferencePinsExactBytesAndSize(t *testing.T) {
	exact := []byte("exact encrypted snapshot")
	ref, err := NewRotationSnapshotReference(exact)
	if err != nil {
		t.Fatalf("NewRotationSnapshotReference() error = %v", err)
	}
	if ref.Size != int64(len(exact)) || ref.SHA256 != sha256Hex(exact) {
		t.Fatalf("reference = %+v, want exact size and digest", ref)
	}
	if err := ref.VerifyExact(exact); err != nil {
		t.Fatalf("VerifyExact(exact) error = %v", err)
	}
	mutated := slices.Clone(exact)
	mutated[0] ^= 1
	if err := ref.VerifyExact(mutated); err == nil {
		t.Fatal("VerifyExact() accepted same-size mutated bytes")
	}
	if err := ref.VerifyExact(append(slices.Clone(exact), 0)); err == nil {
		t.Fatal("VerifyExact() accepted wrong-size bytes")
	}
	for name, invalid := range map[string]RotationSnapshotReference{
		"uppercase digest": {SHA256: strings.Repeat("A", sha256HexLength), Size: 1},
		"zero size":        {SHA256: strings.Repeat("a", sha256HexLength), Size: 0},
		"oversize": {
			SHA256: strings.Repeat("a", sha256HexLength),
			Size:   MaxRotationSnapshotBytes + 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := invalid.Validate(); err == nil {
				t.Fatal("Validate() accepted an invalid snapshot reference")
			}
		})
	}
}

func TestHistoricalGenerationAnchorPinsExactSealBytes(t *testing.T) {
	generationID := "gen-1785400000-deadbeef"
	exact := []byte(`{"schema":"aplane.generation-seal.v2"}`)
	anchor, err := NewHistoricalGenerationAnchor(generationID, exact)
	if err != nil {
		t.Fatalf("NewHistoricalGenerationAnchor() error = %v", err)
	}
	if anchor.GenerationID != generationID ||
		anchor.SealSize != int64(len(exact)) ||
		anchor.SealSHA256 != sha256Hex(exact) {
		t.Fatalf("anchor = %+v, want exact generation, size, and digest", anchor)
	}
	if err := anchor.VerifyExact(generationID, exact); err != nil {
		t.Fatalf("VerifyExact(exact) error = %v", err)
	}
	mutated := slices.Clone(exact)
	mutated[len(mutated)-1] ^= 1
	if err := anchor.VerifyExact(generationID, mutated); err == nil {
		t.Fatal("VerifyExact() accepted mutated seal bytes")
	}
	if err := anchor.VerifyExact("gen-1785400001-feedface", exact); err == nil {
		t.Fatal("VerifyExact() accepted a different generation")
	}
}

func TestNewKeyringFromTermKeysCopiesAndValidatesTerms(t *testing.T) {
	key1 := bytes.Repeat([]byte{1}, argon2KeyLen)
	key2 := bytes.Repeat([]byte{2}, argon2KeyLen)
	kr, err := NewKeyringFromTermKeys(2, map[int64][]byte{1: key1, 2: key2})
	if err != nil {
		t.Fatalf("NewKeyringFromTermKeys() error = %v", err)
	}
	defer kr.Zero()
	ZeroBytes(key1)
	ZeroBytes(key2)
	if kr.CurrentTerm() != 2 {
		t.Fatalf("CurrentTerm() = %d, want 2", kr.CurrentTerm())
	}
	if _, err := kr.Seal([]byte("current"), AccountKeyContext("A")); err != nil {
		t.Fatalf("Seal(current term) error = %v after inputs were zeroed", err)
	}
	if _, err := NewKeyringFromTermKeys(1, map[int64][]byte{
		1: bytes.Repeat([]byte{1}, argon2KeyLen),
		2: bytes.Repeat([]byte{2}, argon2KeyLen),
	}); err == nil {
		t.Fatal("NewKeyringFromTermKeys() accepted a non-greatest current term")
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

func TestOpenKeyringStoreRejectsSymlinkRoot(t *testing.T) {
	dir := t.TempDir()
	passphrase := []byte("passphrase")
	kr, err := CreateKeyringStore(dir, passphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	kr.Zero()
	root := KeyringPath(dir)
	target := filepath.Join(dir, "moved-keyring.enc")
	if err := os.Rename(root, target); err != nil {
		t.Fatalf("Rename(keyring) error = %v", err)
	}
	if err := os.Symlink(target, root); err != nil {
		t.Fatalf("Symlink(keyring) error = %v", err)
	}
	if _, err := OpenKeyringStore(dir, passphrase); err == nil {
		t.Fatal("OpenKeyringStore() followed a symlinked keyring root")
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
		marker["layout"] != KeystoreLayoutKeyringV2 {
		t.Fatalf("marker = %v, want version %d layout %q",
			marker, KeyringKeystoreMetadataVersion, KeystoreLayoutKeyringV2)
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
		{"older version", `{"version":4,"layout":"keyring/v1"}`, "only reads stores it initialized"},
		{"unknown layout", `{"version":5,"layout":"invented/v9"}`, "unsupported layout"},
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
		"schema":           func(m map[string]any) { m["schema"] = "aplane.keyring.v3" },
		"envelope_version": func(m map[string]any) { m["envelope_version"] = KeyringFileVersion + 1 },
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
		"schema":      keyringHeaderAAD("aplane.keyring.v3", KeyringFileVersion, argon2Time, argon2Memory, argon2Threads, salt, nonce),
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

// TestOpenKeyringRejectsForeignKDFParameters proves the root cannot compel
// work this release did not choose.
//
// The KDF parameters are read before anything authenticates them — the KEK
// has to exist before the AEAD can verify the header — so whatever OpenKeyring
// accepts is work an edited root can demand. Only this release's own tuple is
// accepted, which leaves no budget to spend.
func TestOpenKeyringRejectsForeignKDFParameters(t *testing.T) {
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
		// Raised: the work an edited root could compel.
		"kdf_time raised":    {"kdf_time", argon2Time + 1},
		"kdf_memory raised":  {"kdf_memory", argon2Memory * 16},
		"kdf_threads raised": {"kdf_threads", argon2Threads + 1},
		// Lowered: weakening the KDF is equally not this release's tuple.
		"kdf_time lowered":   {"kdf_time", argon2Time - 1},
		"kdf_memory lowered": {"kdf_memory", argon2Memory / 2},
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
				t.Fatalf("OpenKeyring() accepted a foreign %s", tc.field)
			}
			if !strings.Contains(err.Error(), "not this release's") {
				t.Fatalf("OpenKeyring() error = %v, want a KDF tuple rejection", err)
			}
		})
	}
}

// TestOpenKeyringAcceptsSettledMultipleTermsButDeniesRetiredAuthority proves
// resident historical keys do not regain current-state read authority.
func TestOpenKeyringAcceptsSettledMultipleTermsButDeniesRetiredAuthority(t *testing.T) {
	passphrase := []byte("keyring-multiple-terms")
	kr, err := NewKeyring()
	if err != nil {
		t.Fatalf("NewKeyring(): %v", err)
	}
	defer kr.Zero()
	retiredEnvelope, err := kr.Seal([]byte("retired"), AccountKeyContext("ACCOUNT"))
	if err != nil {
		t.Fatalf("Seal(retired): %v", err)
	}

	second, err := randomBytes(argon2KeyLen)
	if err != nil {
		t.Fatalf("randomBytes(): %v", err)
	}
	forged := &Keyring{
		terms:       map[int64][]byte{FirstTerm: kr.terms[FirstTerm], FirstTerm + 1: second},
		currentTerm: FirstTerm + 1,
	}
	sealed, err := SealKeyring(forged, passphrase)
	if err != nil {
		t.Fatalf("SealKeyring(): %v", err)
	}
	opened, err := OpenKeyring(sealed, passphrase)
	if err != nil {
		t.Fatalf("OpenKeyring() error = %v", err)
	}
	defer opened.Zero()
	if _, err := opened.Open(retiredEnvelope, AccountKeyContext("ACCOUNT")); err == nil ||
		!strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("Open(retired settled term) error = %v, want authority rejection", err)
	}
	currentEnvelope, err := opened.Seal([]byte("current"), AccountKeyContext("ACCOUNT"))
	if err != nil {
		t.Fatalf("Seal(current): %v", err)
	}
	if _, err := opened.Open(currentEnvelope, AccountKeyContext("ACCOUNT")); err != nil {
		t.Fatalf("Open(current) error = %v", err)
	}
}

// TestOpenKeyringZeroesRejectedTermKeys proves invalid authenticated
// multi-term payloads do not leave decoded keys on the heap.
func TestOpenKeyringZeroesRejectedTermKeys(t *testing.T) {
	passphrase := []byte("keyring-rejected-cleanup")
	key1 := bytes.Repeat([]byte{1}, argon2KeyLen)
	key2 := bytes.Repeat([]byte{2}, argon2KeyLen)
	valid := func() keyringPayload {
		return keyringPayload{
			Schema:            KeyringSchema,
			CurrentTerm:       2,
			Terms:             []sealedTerm{{Term: 1, Key: key1}, {Term: 2, Key: key2}},
			HistoricalAnchors: []HistoricalGenerationAnchor{},
		}
	}
	cases := map[string]func(*keyringPayload){
		"duplicate term": func(payload *keyringPayload) {
			payload.Terms[1].Term = payload.Terms[0].Term
		},
		"current not greatest": func(payload *keyringPayload) {
			payload.CurrentTerm = payload.Terms[0].Term
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			payload := valid()
			mutate(&payload)
			plaintext, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("Marshal(payload): %v", err)
			}
			sealed := sealKeyringPlaintextForTest(t, plaintext, passphrase)

			var decoded [][]byte
			keyringDecodeHook = func(terms []sealedTerm) {
				for i := range terms {
					decoded = append(decoded, terms[i].Key)
				}
			}
			defer func() { keyringDecodeHook = nil }()

			opened, err := OpenKeyring(sealed, passphrase)
			if err == nil {
				opened.Zero()
				t.Fatal("OpenKeyring() accepted a keyring this release must refuse")
			}
			if len(decoded) == 0 {
				t.Fatal("decode hook never fired; the test is not reaching the payload")
			}
			for i, key := range decoded {
				if len(key) == 0 {
					t.Fatalf("decoded term %d was empty; nothing was proved", i)
				}
				for _, b := range key {
					if b != 0 {
						t.Fatalf("decoded term %d survived rejection unzeroed", i)
					}
				}
			}
		})
	}
}

func TestValidateKeyringPayloadV2(t *testing.T) {
	key1 := bytes.Repeat([]byte{1}, argon2KeyLen)
	key2 := bytes.Repeat([]byte{2}, argon2KeyLen)
	digest := strings.Repeat("a", sha256HexLength)
	valid := func() keyringPayload {
		return keyringPayload{
			Schema:      KeyringSchema,
			CurrentTerm: 2,
			Terms: []sealedTerm{
				{Term: 1, Key: slices.Clone(key1)},
				{Term: 2, Key: slices.Clone(key2)},
			},
			HistoricalAnchors: []HistoricalGenerationAnchor{{
				GenerationID: "gen-1700000000-0123abcd",
				SealSize:     123,
				SealSHA256:   digest,
			}},
			Rotation: &rotationDescriptor{
				FromTerm:       1,
				SnapshotSHA256: digest,
				SnapshotSize:   456,
			},
		}
	}

	if err := validateKeyringPayload(ptr(valid())); err != nil {
		t.Fatalf("validateKeyringPayload(valid) error = %v", err)
	}

	cases := map[string]func(*keyringPayload){
		"missing terms": func(p *keyringPayload) { p.Terms = nil },
		"missing anchors array": func(p *keyringPayload) {
			p.HistoricalAnchors = nil
		},
		"duplicate term": func(p *keyringPayload) { p.Terms[1].Term = 1 },
		"current not greatest": func(p *keyringPayload) {
			p.CurrentTerm = 1
			p.Rotation = nil
		},
		"wrong key length": func(p *keyringPayload) { p.Terms[0].Key = []byte{1} },
		"bad generation": func(p *keyringPayload) {
			p.HistoricalAnchors[0].GenerationID = "../generation"
		},
		"uppercase anchor digest": func(p *keyringPayload) {
			p.HistoricalAnchors[0].SealSHA256 = strings.Repeat("A", sha256HexLength)
		},
		"zero anchor size":    func(p *keyringPayload) { p.HistoricalAnchors[0].SealSize = 0 },
		"wrong retiring term": func(p *keyringPayload) { p.Rotation.FromTerm = 2 },
		"skipped appended term": func(p *keyringPayload) {
			p.Terms[1].Term = 3
			p.CurrentTerm = 3
		},
		"bad snapshot digest": func(p *keyringPayload) { p.Rotation.SnapshotSHA256 = "not-a-digest" },
		"zero snapshot size":  func(p *keyringPayload) { p.Rotation.SnapshotSize = 0 },
		"oversize snapshot": func(p *keyringPayload) {
			p.Rotation.SnapshotSize = MaxRotationSnapshotBytes + 1
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			payload := valid()
			mutate(&payload)
			if err := validateKeyringPayload(&payload); err == nil {
				t.Fatal("validateKeyringPayload() accepted invalid v2 state")
			}
		})
	}
}

func TestOpenKeyringStrictJSON(t *testing.T) {
	passphrase := []byte("strict-keyring-json")
	kr := newTestKeyring(t)
	encoded, err := SealKeyring(kr, passphrase)
	if err != nil {
		t.Fatalf("SealKeyring() error = %v", err)
	}

	var outer map[string]any
	if err := json.Unmarshal(encoded, &outer); err != nil {
		t.Fatalf("Unmarshal(outer) error = %v", err)
	}
	outer["unknown"] = true
	unknownOuter, err := json.Marshal(outer)
	if err != nil {
		t.Fatalf("Marshal(outer) error = %v", err)
	}
	if _, err := OpenKeyring(unknownOuter, passphrase); err == nil {
		t.Fatal("OpenKeyring() accepted an unknown outer field")
	}
	if _, err := OpenKeyring(append(slices.Clone(encoded), []byte(` {}`)...), passphrase); err == nil {
		t.Fatal("OpenKeyring() accepted trailing outer JSON")
	}

	validPayload := keyringPayload{
		Schema:            KeyringSchema,
		CurrentTerm:       FirstTerm,
		Terms:             []sealedTerm{{Term: FirstTerm, Key: bytes.Repeat([]byte{7}, argon2KeyLen)}},
		HistoricalAnchors: []HistoricalGenerationAnchor{},
	}
	plain, err := json.Marshal(validPayload)
	if err != nil {
		t.Fatalf("Marshal(payload) error = %v", err)
	}
	unknownInner := bytes.Replace(plain, []byte(`"historical_anchors":[]`), []byte(`"historical_anchors":[],"unknown":true`), 1)
	for name, malformed := range map[string][]byte{
		"unknown inner field": unknownInner,
		"trailing inner JSON": append(slices.Clone(plain), []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			sealed := sealKeyringPlaintextForTest(t, malformed, passphrase)
			opened, err := OpenKeyring(sealed, passphrase)
			if err == nil {
				opened.Zero()
				t.Fatal("OpenKeyring() accepted malformed authenticated payload JSON")
			}
		})
	}
}

func sealKeyringPlaintextForTest(t *testing.T, plaintext, passphrase []byte) []byte {
	t.Helper()
	salt, err := randomBytes(masterSaltLen)
	if err != nil {
		t.Fatalf("randomBytes(salt) error = %v", err)
	}
	kek := deriveMasterKeyParams(passphrase, salt, argon2Time, argon2Memory, argon2Threads)
	defer ZeroBytes(kek)
	gcm, err := newGCM(kek)
	if err != nil {
		t.Fatalf("newGCM() error = %v", err)
	}
	nonce, err := randomBytes(gcm.NonceSize())
	if err != nil {
		t.Fatalf("randomBytes(nonce) error = %v", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, keyringHeaderAAD(
		KeyringSchema, KeyringFileVersion,
		argon2Time, argon2Memory, argon2Threads, salt, nonce,
	))
	encoded, err := json.Marshal(keyringFile{
		Schema:        KeyringSchema,
		EnvelopeVer:   KeyringFileVersion,
		KDFTime:       argon2Time,
		KDFMemory:     argon2Memory,
		KDFThreads:    argon2Threads,
		Salt:          base64.StdEncoding.EncodeToString(salt),
		Nonce:         base64.StdEncoding.EncodeToString(nonce),
		SealedKeyring: base64.StdEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		t.Fatalf("Marshal(keyring file) error = %v", err)
	}
	return encoded
}

func ptr[T any](value T) *T { return &value }

// TestKeyringIntegrityOperationsMatchTheDerivedKeys proves the confined
// operations preserve the established per-domain derivations without
// exposing those derived keys to callers.
//
// Every policy and node-role sidecar already on disk was signed with a key
// from derivePolicyIntegrityKey or deriveNodeRoleIntegrityKey. Phase 2 moves
// the callers to the keyring; if that changed the derivation by even a salt,
// every one of those sidecars would fail verification and the store would
// fail closed on load.
func TestKeyringIntegrityOperationsMatchTheDerivedKeys(t *testing.T) {
	termKey := bytes.Repeat([]byte{0x5A}, argon2KeyLen)
	kr, err := NewKeyringFromKey(termKey)
	if err != nil {
		t.Fatalf("NewKeyringFromKey(): %v", err)
	}
	defer kr.Zero()

	cases := map[string]struct {
		domain  IntegrityDomain
		fromKey func([]byte) ([]byte, error)
	}{
		"policy":    {IntegrityDomainPolicy, derivePolicyIntegrityKey},
		"node role": {IntegrityDomainNodeRole, deriveNodeRoleIntegrityKey},
	}
	payload := []byte("integrity payload")
	macs := make(map[string]string)
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			term, viaKeyring, err := kr.SignIntegrity(tc.domain, payload)
			if err != nil {
				t.Fatalf("SignIntegrity(): %v", err)
			}
			viaKey, err := tc.fromKey(termKey)
			if err != nil {
				t.Fatalf("raw-key derivation: %v", err)
			}
			defer ZeroBytes(viaKey)
			if viaKeyring != computeIntegrityMAC(payload, viaKey) {
				t.Fatal("keyring derivation diverged; every sidecar on disk would stop verifying")
			}
			if err := kr.VerifyIntegrity(tc.domain, payload, term, viaKeyring); err != nil {
				t.Fatalf("VerifyIntegrity(): %v", err)
			}
			macs[name] = viaKeyring
		})
	}

	// The two domains must not collide, or a policy sidecar would verify
	// under the node-role key.
	if macs["policy"] == macs["node role"] {
		t.Fatal("policy and node-role integrity MACs are identical")
	}
	if err := kr.VerifyIntegrity(
		IntegrityDomainNodeRole,
		payload,
		FirstTerm,
		macs["policy"],
	); err == nil {
		t.Fatal("policy MAC verified in the node-role domain")
	}
	if err := kr.VerifyIntegrity(
		IntegrityDomainPolicy,
		payload,
		FirstTerm+1,
		macs["policy"],
	); err == nil {
		t.Fatal("MAC under an unauthorized term verified")
	}
}

// TestOpenKeyringStoreRejectsUnsupportedMarkerVersion proves the format gate
// refuses a store this release did not initialize.
//
// The marker is the only thing standing between a binary and a store written
// in a layout it does not understand, and its rejection has to be actionable:
// the operator's route forward is a backup archive into a fresh store, not a
// migration, so the error has to say that.
func TestOpenKeyringStoreRejectsUnsupportedMarkerVersion(t *testing.T) {
	passphrase := []byte("marker-version-gate")
	dir := t.TempDir()
	kr, err := CreateKeyringStore(dir, passphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore(): %v", err)
	}
	kr.Zero()

	markerPath := filepath.Join(dir, keystoreMetaFile)
	cases := map[string]struct {
		marker map[string]any
		want   string
	}{
		"older version": {
			map[string]any{"version": KeyringKeystoreMetadataVersion - 1, "layout": KeystoreLayoutKeyringV2},
			"restore from a backup archive",
		},
		"newer version": {
			map[string]any{"version": KeyringKeystoreMetadataVersion + 1, "layout": KeystoreLayoutKeyringV2},
			"restore from a backup archive",
		},
		"right version, foreign layout": {
			map[string]any{"version": KeyringKeystoreMetadataVersion, "layout": "generations/v1"},
			"unsupported layout",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(tc.marker)
			if err != nil {
				t.Fatalf("Marshal(): %v", err)
			}
			if err := os.WriteFile(markerPath, encoded, 0o600); err != nil {
				t.Fatalf("WriteFile(): %v", err)
			}
			opened, err := OpenKeyringStore(dir, passphrase)
			if err == nil {
				opened.Zero()
				t.Fatal("OpenKeyringStore() accepted a marker this release cannot read")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("OpenKeyringStore() error = %v, want it to mention %q", err, tc.want)
			}
		})
	}

	// The gate runs before the root is touched: a store whose marker is
	// unreadable must not have its keyring unwrapped on the way to failing.
	if err := os.WriteFile(markerPath, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}
	if opened, err := OpenKeyringStore(dir, passphrase); err == nil {
		opened.Zero()
		t.Fatal("OpenKeyringStore() accepted an unparseable marker")
	}
}
