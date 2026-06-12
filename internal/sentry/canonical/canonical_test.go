// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package canonical

import (
	"encoding/hex"
	"testing"

	"github.com/aplane-algo/aplane/internal/txnutil"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

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

func TestDecodeGroupHexSingleton(t *testing.T) {
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

	got, err := DecodeGroupHex([]string{txnutil.EncodeWithPrefixHex(txn)})
	if err != nil {
		t.Fatalf("DecodeGroupHex() error = %v", err)
	}
	if len(got.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(got.Entries))
	}
	if got.Entries[0].Txn.Sender != txn.Sender {
		t.Fatalf("sender = %s, want %s", got.Entries[0].Txn.Sender, txn.Sender)
	}
}

func TestDecodeGroupHexRejectsGroupedSingleton(t *testing.T) {
	txn := types.Transaction{Type: types.PaymentTx}
	txn.Group = types.Digest{1}
	_, err := DecodeGroupHex([]string{txnutil.EncodeWithPrefixHex(txn)})
	if err == nil {
		t.Fatal("DecodeGroupHex() accepted grouped singleton")
	}
}

func TestDecodeGroupHexValidatesComputedGroup(t *testing.T) {
	txnA := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{1}}}
	txnB := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{2}}}
	groupID, err := algocrypto.ComputeGroupID([]types.Transaction{txnA, txnB})
	if err != nil {
		t.Fatalf("ComputeGroupID() error = %v", err)
	}
	txnA.Group = groupID
	txnB.Group = groupID
	if _, err := DecodeGroupHex([]string{txnutil.EncodeWithPrefixHex(txnA), txnutil.EncodeWithPrefixHex(txnB)}); err != nil {
		t.Fatalf("DecodeGroupHex() error = %v", err)
	}

	txnB.Note = []byte("changed")
	if _, err := DecodeGroupHex([]string{txnutil.EncodeWithPrefixHex(txnA), txnutil.EncodeWithPrefixHex(txnB)}); err == nil {
		t.Fatal("DecodeGroupHex() accepted wrong computed group")
	}
}
