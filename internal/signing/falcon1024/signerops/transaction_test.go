// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"bytes"
	"strings"
	"testing"

	"github.com/algorand/falcon"
	"github.com/algorand/go-algorand-sdk/v2/types"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

func TestAuthorizeAndValidateTransaction(t *testing.T) {
	publicKey, privateKey, salt, authorizer := testKey(t)
	direct := types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: authorizer, Fee: 3_000_000, FirstValid: 1, LastValid: 2},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: types.Address{9}, Amount: 1},
	}
	stxn, err := AuthorizeTransaction(privateKey, publicKey, salt, direct, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	if !stxn.AuthAddr.IsZero() {
		t.Fatalf("direct AuthAddr = %s, want zero", stxn.AuthAddr)
	}
	if err := ValidateTransaction(stxn, direct, authorizer); err != nil {
		t.Fatalf("ValidateTransaction(direct): %v", err)
	}

	rekeyed := direct
	rekeyed.Sender = types.Address{7}
	stxn, err = AuthorizeTransaction(privateKey, publicKey, salt, rekeyed, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	if stxn.AuthAddr != authorizer {
		t.Fatalf("rekeyed AuthAddr = %s, want %s", stxn.AuthAddr, authorizer)
	}
	if err := ValidateTransaction(stxn, rekeyed, authorizer); err != nil {
		t.Fatalf("ValidateTransaction(rekeyed): %v", err)
	}
}

func TestValidateTransactionRejectsTamperingAndAmbiguousAuthorization(t *testing.T) {
	publicKey, privateKey, salt, authorizer := testKey(t)
	txn := types.Transaction{
		Type:   types.PaymentTx,
		Header: types.Header{Sender: authorizer, Fee: 3_000_000, FirstValid: 1, LastValid: 2},
	}
	valid, err := AuthorizeTransaction(privateKey, publicKey, salt, txn, authorizer)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		edit func(*types.SignedTxn)
		want string
	}{
		{"transaction", func(stxn *types.SignedTxn) { stxn.Txn.Note = []byte("changed") }, "changed the transaction"},
		{"scheme", func(stxn *types.SignedTxn) { stxn.PQsig.Scheme = types.PQScheme{'x', '1'} }, "scheme"},
		{"signature", func(stxn *types.SignedTxn) { stxn.PQsig.Signature[0] ^= 0xff }, "verify"},
		{"public key", func(stxn *types.SignedTxn) { stxn.PQsig.PublicKey = stxn.PQsig.PublicKey[:2] }, "public key length"},
		{"ed25519 plus pq", func(stxn *types.SignedTxn) { stxn.Sig[0] = 1 }, "multiple authorization"},
		{"nested pq plus pq", func(stxn *types.SignedTxn) { stxn.Lsig.PQsig.Scheme[0] = 1 }, "multiple authorization"},
		{"unexpected auth addr", func(stxn *types.SignedTxn) { stxn.AuthAddr = types.Address{4} }, "AuthAddr"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stxn := valid
			stxn.PQsig.PublicKey = append([]byte(nil), valid.PQsig.PublicKey...)
			stxn.PQsig.Signature = append([]byte(nil), valid.PQsig.Signature...)
			test.edit(&stxn)
			err := ValidateTransaction(stxn, txn, authorizer)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateTransaction() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func testKey(t *testing.T) ([]byte, *falcon.PrivateKey, byte, types.Address) {
	t.Helper()
	seed := bytes.Repeat([]byte{23}, nativefalcon.RecoveryEntropySize)
	publicKey, privateKey, err := falcon.GenerateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	salt, authorizer, err := nativefalcon.CanonicalAddress(publicKey[:])
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), publicKey[:]...), &privateKey, salt, authorizer
}
