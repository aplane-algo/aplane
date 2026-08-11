// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package harness

import (
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	algomnemonic "github.com/algorand/go-algorand-sdk/v2/mnemonic"
	"github.com/algorand/go-algorand-sdk/v2/types"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	nativefalconops "github.com/aplane-algo/aplane/internal/signing/falcon1024/signerops"
)

func TestNativeFundingMnemonicDerivationAndSigning(t *testing.T) {
	mnemonicWords := nativeFundingTestMnemonic(t)
	authorizer, err := nativeFalconAuthorizerFromMnemonic(mnemonicWords)
	if err != nil {
		t.Fatalf("nativeFalconAuthorizerFromMnemonic() error = %v", err)
	}
	defer authorizer.zero()

	address, err := NativeFundingAddressFromMnemonic(mnemonicWords)
	if err != nil {
		t.Fatalf("NativeFundingAddressFromMnemonic() error = %v", err)
	}
	if address != authorizer.address.String() {
		t.Fatalf("NativeFundingAddressFromMnemonic() = %s, want %s", address, authorizer.address)
	}
	if !nativefalcon.IsCompliant(authorizer.address) {
		t.Fatalf("derived native Falcon address %s is on the Ed25519 curve", authorizer.address)
	}

	funder := &FundTestAccount{authorizer: authorizer}
	txn := types.Transaction{
		Header: types.Header{
			Sender: authorizer.address,
			Fee:    1_000,
		},
	}
	prepared, err := funder.PrepareTransaction(txn, 1_000)
	if err != nil {
		t.Fatalf("PrepareTransaction() error = %v", err)
	}
	if prepared.Fee != 3_000 {
		t.Fatalf("PrepareTransaction() fee = %d, want 3000", prepared.Fee)
	}
	_, signedBytes, err := funder.SignTransaction(prepared)
	if err != nil {
		t.Fatalf("SignTransaction() error = %v", err)
	}
	var signed types.SignedTxn
	if err := msgpack.Decode(signedBytes, &signed); err != nil {
		t.Fatalf("decode signed transaction: %v", err)
	}
	if err := nativefalconops.ValidateTransaction(signed, prepared, authorizer.address); err != nil {
		t.Fatalf("ValidateTransaction() error = %v", err)
	}
}

func TestPrepareTransactionPreservesExistingFeeAndUsesDefaultMinimum(t *testing.T) {
	funder := &FundTestAccount{authorizer: &nativeFalconAuthorizer{}}
	prepared, err := funder.PrepareTransaction(types.Transaction{
		Header: types.Header{Fee: 2_000},
	}, 0)
	if err != nil {
		t.Fatalf("PrepareTransaction() error = %v", err)
	}
	if prepared.Fee != 4_000 {
		t.Fatalf("PrepareTransaction() fee = %d, want 4000", prepared.Fee)
	}
}

func nativeFundingTestMnemonic(t *testing.T) string {
	t.Helper()
	entropy := make([]byte, nativefalcon.RecoveryEntropySize)
	for i := range entropy {
		entropy[i] = byte(i + 1)
	}
	words, err := algomnemonic.FromKey(entropy)
	if err != nil {
		t.Fatalf("mnemonic.FromKey() error = %v", err)
	}
	return words
}
