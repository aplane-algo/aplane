// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package message

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The cosigner signs a domain-tagged message, never the raw TxID the spending
// key signs, so neither signature can stand in for the other.
func TestComponentMessageSeparatesTheCosignerFromTheSpendingKey(t *testing.T) {
	var txid [32]byte
	for i := range txid {
		txid[i] = byte(i)
	}
	cosigner := ComponentMessage(RoleCosigner, txid)
	if bytes.Equal(cosigner[:], txid[:]) {
		t.Fatal("cosigner component message is the TxID")
	}
}

func TestComponentMessageBytesValidation(t *testing.T) {
	if _, err := ComponentMessageBytes(RoleCosigner, make([]byte, 31)); err == nil {
		t.Fatal("ComponentMessageBytes accepted short txid")
	}
	for _, role := range []Role{0x01, 99} {
		if _, err := ComponentMessageBytes(role, make([]byte, 32)); err == nil {
			t.Fatalf("ComponentMessageBytes accepted role %d", role)
		}
	}
}

func TestComponentMessageKnownVectors(t *testing.T) {
	txid := make([]byte, 32)
	for i := range txid {
		txid[i] = byte(i)
	}
	got, err := ComponentMessageBytes(RoleCosigner, txid)
	if err != nil {
		t.Fatalf("ComponentMessageBytes() error = %v", err)
	}
	if want := "fb26b88a40894de1c59e3f64a8a10349f7eb32092630e39b2d610fe098b9ebce"; hex.EncodeToString(got[:]) != want {
		t.Fatalf("ComponentMessageBytes() = %s, want %s", hex.EncodeToString(got[:]), want)
	}
}
