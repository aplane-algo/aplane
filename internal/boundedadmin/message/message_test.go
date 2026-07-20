// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package message

import (
	"crypto/sha512"
	"encoding/hex"
	"testing"
)

func TestAdminMessageFrozenVector(t *testing.T) {
	binding, err := hex.DecodeString("f99ef1b6430b4dc5bfc382a69299d2a94fcd140a326ed50900e228c18d4aa264")
	if err != nil {
		t.Fatal(err)
	}
	txID := make([]byte, 32)
	for i := range txID {
		txID[i] = 0x44
	}
	got, err := AdminMessage(OperationRekey, binding, txID)
	if err != nil {
		t.Fatal(err)
	}
	const want = "a98ffd421aa7ef24d9d459a9950c583f5bce41ff0832fbaa168dd106473fe8ae"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("AdminMessage() = %x, want %s", got, want)
	}
}

func TestPrefixAndMessageAgree(t *testing.T) {
	binding := make([]byte, 32)
	txID := make([]byte, 32)
	prefix, err := Prefix(OperationRekey, binding)
	if err != nil {
		t.Fatal(err)
	}
	transcript := append(append([]byte(nil), prefix...), txID...)
	got := sha512.Sum512_256(transcript)
	want, err := AdminMessage(OperationRekey, binding, txID)
	if err != nil {
		t.Fatal(err)
	}
	// The on-chain path hashes Prefix || TxID.
	if got != want {
		t.Fatalf("hash(Prefix || TxID) = %x, want %x", got, want)
	}
}

func TestAdminMessageRejectsUnknownOperationAndLengths(t *testing.T) {
	if _, err := AdminMessage("close", make([]byte, 32), make([]byte, 32)); err == nil {
		t.Fatal("AdminMessage() accepted unknown operation")
	}
	if _, err := AdminMessage(OperationRekey, make([]byte, 31), make([]byte, 32)); err == nil {
		t.Fatal("AdminMessage() accepted short binding")
	}
	if _, err := AdminMessage(OperationRekey, make([]byte, 32), make([]byte, 31)); err == nil {
		t.Fatal("AdminMessage() accepted short transaction ID")
	}
}
