// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package verify

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/aplane-algo/aplane/internal/txnutil"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

func TestVerifyEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	msg := []byte("message")
	sig := ed25519.Sign(priv, msg)
	if err := VerifyEd25519(pub, msg, sig); err != nil {
		t.Fatalf("VerifyEd25519() error = %v", err)
	}
	sig[0] ^= 0xff
	if err := VerifyEd25519(pub, msg, sig); err == nil {
		t.Fatal("VerifyEd25519() accepted tampered signature")
	}
}

func TestVerifyFalcon1024(t *testing.T) {
	seed := make([]byte, 48)
	for i := range seed {
		seed[i] = byte(i)
	}
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	msg := []byte("message")
	sig, err := kp.Sign(msg)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if err := VerifyFalcon1024(kp.PublicKey[:], msg, sig); err != nil {
		t.Fatalf("VerifyFalcon1024() error = %v", err)
	}
	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0xff
	if err := VerifyFalcon1024(kp.PublicKey[:], msg, tampered); err == nil {
		t.Fatal("VerifyFalcon1024() accepted tampered signature")
	}
}

func TestGroupHashKnownVector(t *testing.T) {
	got, err := GroupHash([][]byte{[]byte("TXone"), []byte("TXtwo")})
	if err != nil {
		t.Fatalf("GroupHash() error = %v", err)
	}
	const want = "b89b9181bb481333c7083713fdd98b3c7b34eee9bcace1fd899d20b508243ed7"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("GroupHash() = %s, want %s", hex.EncodeToString(got[:]), want)
	}
}

func TestDecodeCanonicalGroupHexSingleton(t *testing.T) {
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      types.Address{1},
			Fee:         1000,
			FirstValid:  1,
			LastValid:   10,
			GenesisHash: types.Digest{9},
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: types.Address{2},
			Amount:   1,
		},
	}

	got, err := DecodeCanonicalGroupHex([]string{txnutil.EncodeWithPrefixHex(txn)})
	if err != nil {
		t.Fatalf("DecodeCanonicalGroupHex() error = %v", err)
	}
	if len(got.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(got.Entries))
	}
	if got.Entries[0].Txn.Sender != txn.Sender {
		t.Fatalf("sender = %s, want %s", got.Entries[0].Txn.Sender, txn.Sender)
	}
}

func TestDecodeCanonicalGroupHexRejectsGroupedSingleton(t *testing.T) {
	txn := types.Transaction{Type: types.PaymentTx}
	txn.Group = types.Digest{1}
	_, err := DecodeCanonicalGroupHex([]string{txnutil.EncodeWithPrefixHex(txn)})
	if err == nil {
		t.Fatal("DecodeCanonicalGroupHex() accepted grouped singleton")
	}
}

func TestDecodeCanonicalGroupHexValidatesComputedGroup(t *testing.T) {
	txnA := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{1}}}
	txnB := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{2}}}
	groupID, err := algocrypto.ComputeGroupID([]types.Transaction{txnA, txnB})
	if err != nil {
		t.Fatalf("ComputeGroupID() error = %v", err)
	}
	txnA.Group = groupID
	txnB.Group = groupID
	if _, err := DecodeCanonicalGroupHex([]string{txnutil.EncodeWithPrefixHex(txnA), txnutil.EncodeWithPrefixHex(txnB)}); err != nil {
		t.Fatalf("DecodeCanonicalGroupHex() error = %v", err)
	}

	txnB.Note = []byte("changed")
	if _, err := DecodeCanonicalGroupHex([]string{txnutil.EncodeWithPrefixHex(txnA), txnutil.EncodeWithPrefixHex(txnB)}); err == nil {
		t.Fatal("DecodeCanonicalGroupHex() accepted wrong computed group")
	}
}
