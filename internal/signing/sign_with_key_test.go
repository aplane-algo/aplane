// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"crypto/ed25519"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func paymentFrom(sender types.Address) types.Transaction {
	return types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: sender, Fee: 1000, FirstValid: 10, LastValid: 20,
			GenesisID: "test-v1", GenesisHash: types.Digest{1},
		},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: types.Address{2}, Amount: 1},
	}
}

// SignTransactionWithKey signs for the key's own account without an auth
// address, signs for another sender by setting the key's address as AuthAddr,
// and returns the transaction ID of the transaction it was given.
func TestSignTransactionWithKey(t *testing.T) {
	acct := crypto.GenerateAccount()

	own := paymentFrom(acct.Address)
	txid, raw, err := SignTransactionWithKey(acct.PrivateKey, own)
	if err != nil {
		t.Fatal(err)
	}
	if txid != crypto.GetTxID(own) {
		t.Fatalf("txid %s, want %s", txid, crypto.GetTxID(own))
	}
	var stxn types.SignedTxn
	if err := msgpack.Decode(raw, &stxn); err != nil {
		t.Fatal(err)
	}
	if stxn.AuthAddr != (types.Address{}) {
		t.Fatalf("auth address %s set for the key's own account", stxn.AuthAddr)
	}
	if !ed25519.Verify(acct.PublicKey, append([]byte("TX"), msgpack.Encode(own)...), stxn.Sig[:]) {
		t.Fatal("signature does not verify over TX || msgpack(txn)")
	}

	other := paymentFrom(types.Address{9})
	_, raw, err = SignTransactionWithKey(acct.PrivateKey, other)
	if err != nil {
		t.Fatal(err)
	}
	if err := msgpack.Decode(raw, &stxn); err != nil {
		t.Fatal(err)
	}
	if stxn.AuthAddr != acct.Address {
		t.Fatalf("auth address %s, want the signing key's address %s", stxn.AuthAddr, acct.Address)
	}

	if _, _, err := SignTransactionWithKey(ed25519.PrivateKey{1, 2, 3}, own); err == nil {
		t.Fatal("malformed private key accepted")
	}
}
