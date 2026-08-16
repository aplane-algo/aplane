// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientsign

import (
	"strings"
	"testing"

	sdkcrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signing"
)

func verificationPayment(sender, receiver byte) types.Transaction {
	return types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      types.Address{sender},
			Fee:         1000,
			FirstValid:  10,
			LastValid:   20,
			GenesisID:   "verify-test-v1",
			GenesisHash: types.Digest{9},
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: types.Address{receiver},
			Amount:   1,
		},
	}
}

func testSignedBytes(txn types.Transaction) []byte {
	var sig types.Signature
	sig[0] = 1
	return msgpack.Encode(types.SignedTxn{Txn: txn, Sig: sig})
}

func decodeVerificationSigned(t *testing.T, encoded [][]byte) []types.SignedTxn {
	t.Helper()
	result := make([]types.SignedTxn, len(encoded))
	for i := range encoded {
		if err := msgpack.Decode(encoded[i], &result[i]); err != nil {
			t.Fatalf("decode signed transaction %d: %v", i, err)
		}
	}
	return result
}

func TestValidateSignedGroupMutationsAcceptsReportedFeeIncrease(t *testing.T) {
	original := verificationPayment(1, 2)
	returned := original
	returned.Fee = 3000
	encoded := [][]byte{testSignedBytes(returned)}
	report := &signerapi.MutationReport{
		OriginalCount:  1,
		FinalCount:     1,
		FeesModified:   []int{0},
		TotalFeesDelta: 2000,
	}
	if err := validateSignedGroupMutations(
		[]types.Transaction{original}, decodeVerificationSigned(t, encoded), encoded, report,
	); err != nil {
		t.Fatalf("valid reported fee increase: %v", err)
	}
}

func TestValidateSignedGroupMutationsRejectsUnreportedChanges(t *testing.T) {
	original := verificationPayment(1, 2)

	t.Run("transaction body", func(t *testing.T) {
		returned := original
		returned.Receiver = types.Address{3}
		encoded := [][]byte{testSignedBytes(returned)}
		err := validateSignedGroupMutations([]types.Transaction{original}, decodeVerificationSigned(t, encoded), encoded, nil)
		if err == nil || !strings.Contains(err.Error(), "unreported fields") {
			t.Fatalf("error = %v, want unreported-fields rejection", err)
		}
	})

	t.Run("fee", func(t *testing.T) {
		returned := original
		returned.Fee++
		encoded := [][]byte{testSignedBytes(returned)}
		err := validateSignedGroupMutations([]types.Transaction{original}, decodeVerificationSigned(t, encoded), encoded, nil)
		if err == nil || !strings.Contains(err.Error(), "unreported fields") {
			t.Fatalf("error = %v, want unreported-fee rejection", err)
		}
	})
}

func TestValidateSignedGroupMutationsAcceptsCanonicalDummy(t *testing.T) {
	original := verificationPayment(1, 2)
	dummies, err := signing.CreateDummyTransactions(1, suggestedParamsFromTransaction(original))
	if err != nil {
		t.Fatal(err)
	}
	final := []types.Transaction{original, dummies[0]}
	gid, err := sdkcrypto.ComputeGroupID(final)
	if err != nil {
		t.Fatal(err)
	}
	for i := range final {
		final[i].Group = gid
	}
	dummySigned, err := signing.SignDummyTransaction(final[1])
	if err != nil {
		t.Fatal(err)
	}
	encoded := [][]byte{testSignedBytes(final[0]), msgpack.Encode(dummySigned)}
	report := &signerapi.MutationReport{
		DummiesAdded:   1,
		GroupIDChanged: true,
		OriginalCount:  1,
		FinalCount:     2,
	}
	if err := validateSignedGroupMutations(
		[]types.Transaction{original}, decodeVerificationSigned(t, encoded), encoded, report,
	); err != nil {
		t.Fatalf("valid canonical dummy: %v", err)
	}
}

func TestValidateSignedGroupMutationsRejectsNonCanonicalDummy(t *testing.T) {
	original := verificationPayment(1, 2)
	dummies, err := signing.CreateDummyTransactions(1, suggestedParamsFromTransaction(original))
	if err != nil {
		t.Fatal(err)
	}
	dummies[0].Note = []byte("not-canonical")
	final := []types.Transaction{original, dummies[0]}
	gid, err := sdkcrypto.ComputeGroupID(final)
	if err != nil {
		t.Fatal(err)
	}
	for i := range final {
		final[i].Group = gid
	}
	dummySigned, err := signing.SignDummyTransaction(final[1])
	if err != nil {
		t.Fatal(err)
	}
	encoded := [][]byte{testSignedBytes(final[0]), msgpack.Encode(dummySigned)}
	report := &signerapi.MutationReport{
		DummiesAdded:   1,
		GroupIDChanged: true,
		OriginalCount:  1,
		FinalCount:     2,
	}
	err = validateSignedGroupMutations(
		[]types.Transaction{original}, decodeVerificationSigned(t, encoded), encoded, report,
	)
	if err == nil || !strings.Contains(err.Error(), "not the canonical resource dummy") {
		t.Fatalf("error = %v, want canonical-dummy rejection", err)
	}
}

func TestValidateSignedGroupMutationsRejectsNonCanonicalDummyAuthorization(t *testing.T) {
	original := verificationPayment(1, 2)
	dummies, err := signing.CreateDummyTransactions(1, suggestedParamsFromTransaction(original))
	if err != nil {
		t.Fatal(err)
	}
	final := []types.Transaction{original, dummies[0]}
	gid, err := sdkcrypto.ComputeGroupID(final)
	if err != nil {
		t.Fatal(err)
	}
	for i := range final {
		final[i].Group = gid
	}
	encoded := [][]byte{testSignedBytes(final[0]), testSignedBytes(final[1])}
	report := &signerapi.MutationReport{
		DummiesAdded:   1,
		GroupIDChanged: true,
		OriginalCount:  1,
		FinalCount:     2,
	}
	err = validateSignedGroupMutations(
		[]types.Transaction{original}, decodeVerificationSigned(t, encoded), encoded, report,
	)
	if err == nil || !strings.Contains(err.Error(), "canonical resource dummy authorization") {
		t.Fatalf("error = %v, want dummy-authorization rejection", err)
	}
}

func TestValidateSignedGroupMutationsRejectsNonCanonicalGroupID(t *testing.T) {
	original := []types.Transaction{verificationPayment(1, 2), verificationPayment(3, 4)}
	returned := append([]types.Transaction(nil), original...)
	for i := range returned {
		returned[i].Group = types.Digest{0xff}
	}
	encoded := [][]byte{testSignedBytes(returned[0]), testSignedBytes(returned[1])}
	report := &signerapi.MutationReport{
		GroupIDChanged: true,
		OriginalCount:  2,
		FinalCount:     2,
	}
	err := validateSignedGroupMutations(original, decodeVerificationSigned(t, encoded), encoded, report)
	if err == nil || !strings.Contains(err.Error(), "canonical group ID") {
		t.Fatalf("error = %v, want canonical-group rejection", err)
	}
}

func TestValidateSignedGroupMutationsRejectsInaccurateReport(t *testing.T) {
	original := verificationPayment(1, 2)
	returned := original
	returned.Fee = 2000
	encoded := [][]byte{testSignedBytes(returned)}
	report := &signerapi.MutationReport{
		OriginalCount:  1,
		FinalCount:     1,
		FeesModified:   []int{0},
		TotalFeesDelta: 999,
	}
	err := validateSignedGroupMutations(
		[]types.Transaction{original}, decodeVerificationSigned(t, encoded), encoded, report,
	)
	if err == nil || !strings.Contains(err.Error(), "does not match observed delta") {
		t.Fatalf("error = %v, want fee-delta rejection", err)
	}
}

func suggestedParamsFromTransaction(txn types.Transaction) types.SuggestedParams {
	return types.SuggestedParams{
		Fee:             txn.Fee,
		FirstRoundValid: txn.FirstValid,
		LastRoundValid:  txn.LastValid,
		GenesisID:       txn.GenesisID,
		GenesisHash:     txn.GenesisHash[:],
		FlatFee:         true,
	}
}
