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

// The vector pins the message every cosigned program checks, role byte
// included: a change to it changes on-chain behaviour.
func TestComponentMessageKnownVectors(t *testing.T) {
	var txid [32]byte
	for i := range txid {
		txid[i] = byte(i)
	}
	got := ComponentMessage(RoleCosigner, txid)
	if want := "fb26b88a40894de1c59e3f64a8a10349f7eb32092630e39b2d610fe098b9ebce"; hex.EncodeToString(got[:]) != want {
		t.Fatalf("ComponentMessage() = %s, want %s", hex.EncodeToString(got[:]), want)
	}
	retired := ComponentMessage(Role(0x01), txid)
	if bytes.Equal(retired[:], got[:]) {
		t.Fatal("the retired user role signs the cosigner's message")
	}
}
