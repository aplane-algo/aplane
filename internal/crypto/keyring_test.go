// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"bytes"
	"encoding/json"
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
