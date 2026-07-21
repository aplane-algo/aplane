// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package witness

import (
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestPublicReferenceRoundTrip(t *testing.T) {
	publicKey := make([]byte, Falcon1024PublicKeySize)
	for i := range publicKey {
		publicKey[i] = byte(i)
	}
	keyID, err := ID(Falcon1024V1, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := NewPublicReference(Falcon1024V1, keyID, hex.EncodeToString(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(reference)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePublicReference(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != reference {
		t.Fatalf("parsed reference = %#v, want %#v", parsed, reference)
	}
}

func TestPublicReferenceRejectsUnknownFieldAndMismatchedID(t *testing.T) {
	publicKey := make([]byte, Falcon1024PublicKeySize)
	keyID, err := ID(Falcon1024V1, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyHex := hex.EncodeToString(publicKey)
	if _, err := ParsePublicReference([]byte(`{"schema":"aplane.witness-key-public.v1","key_type":"aplane.witness-falcon1024.v1","witness_key_id":"` + keyID + `","public_key_hex":"` + publicKeyHex + `","extra":true}`)); err == nil {
		t.Fatal("unknown field was accepted")
	}
	if _, err := NewPublicReference(Falcon1024V1, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", publicKeyHex); err == nil {
		t.Fatal("mismatched witness key ID was accepted")
	}
}
