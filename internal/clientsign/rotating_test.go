// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientsign

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

var (
	rotatingAccount = types.Address{1}
	rotatingTarget  = types.Address{2}
)

func rotatingOriginal() types.Transaction {
	return types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: rotatingAccount, Fee: 1000, FirstValid: 1000, LastValid: 1100,
			GenesisID: "testnet-v1.0", GenesisHash: types.Digest{9},
		},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: types.Address{5}, Amount: 7},
	}
}

// preparedFor builds the response an honest signer returns, after mutate
// changes the group.
func preparedFor(t *testing.T, original types.Transaction, rekeyTo types.Address, mutate func([]types.Transaction)) *signerapi.RotatingPrepareResponse {
	t.Helper()
	spend := original
	spend.RekeyTo = rekeyTo
	spend.Fee = 4000
	dummies, err := signing.CreateDummyTransactions(1, types.SuggestedParams{
		Fee: original.Fee, FirstRoundValid: original.FirstValid, LastRoundValid: original.LastValid,
		GenesisID: original.GenesisID, GenesisHash: original.GenesisHash[:], FlatFee: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	txns := append([]types.Transaction{spend}, dummies...)
	if mutate != nil {
		mutate(txns)
	}
	gid, err := algocrypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatal(err)
	}
	encoded := make([]string, len(txns))
	for i := range txns {
		txns[i].Group = gid
		encoded[i] = hex.EncodeToString(txnutil.EncodeWithPrefix(txns[i]))
	}
	return &signerapi.RotatingPrepareResponse{
		Account: original.Sender.String(), Stage: 3, Target: 4, RekeyTo: rekeyTo.String(), Transactions: encoded,
	}
}

func TestValidatePreparedRotatingGroupAcceptsHonestPreparation(t *testing.T) {
	original := rotatingOriginal()
	txns, err := ValidatePreparedRotatingGroup(original, preparedFor(t, original, rotatingTarget, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(txns) != 2 || txns[0].RekeyTo != rotatingTarget {
		t.Fatalf("validated group = %d txns, rekey %s", len(txns), txns[0].RekeyTo)
	}
}

func TestValidatePreparedRotatingGroupRejectsTampering(t *testing.T) {
	original := rotatingOriginal()
	tests := []struct {
		name string
		resp func() *signerapi.RotatingPrepareResponse
		want string
	}{
		{name: "changed receiver", resp: func() *signerapi.RotatingPrepareResponse {
			return preparedFor(t, original, rotatingTarget, func(tx []types.Transaction) { tx[0].Receiver = types.Address{6} })
		}, want: "other than"},
		{name: "changed amount", resp: func() *signerapi.RotatingPrepareResponse {
			return preparedFor(t, original, rotatingTarget, func(tx []types.Transaction) { tx[0].Amount = 8 })
		}, want: "other than"},
		{name: "lowered fee", resp: func() *signerapi.RotatingPrepareResponse {
			return preparedFor(t, original, rotatingTarget, func(tx []types.Transaction) { tx[0].Fee = 10 })
		}, want: "lowered"},
		{name: "non-canonical dummy", resp: func() *signerapi.RotatingPrepareResponse {
			return preparedFor(t, original, rotatingTarget, func(tx []types.Transaction) { tx[1].Note = []byte("x") })
		}, want: "canonical resource dummy"},
		{name: "rekey to sender", resp: func() *signerapi.RotatingPrepareResponse {
			return preparedFor(t, original, rotatingAccount, nil)
		}, want: "another"},
		{name: "reported rekey differs", resp: func() *signerapi.RotatingPrepareResponse {
			r := preparedFor(t, original, rotatingTarget, nil)
			r.RekeyTo = types.Address{3}.String()
			return r
		}, want: "other than"},
		{name: "wrong account", resp: func() *signerapi.RotatingPrepareResponse {
			r := preparedFor(t, original, rotatingTarget, nil)
			r.Account = types.Address{4}.String()
			return r
		}, want: "not the sender"},
		{name: "target not the next stage", resp: func() *signerapi.RotatingPrepareResponse {
			r := preparedFor(t, original, rotatingTarget, nil)
			r.Target = r.Stage + 2
			return r
		}, want: "not the stage after"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidatePreparedRotatingGroup(original, tt.resp())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateSignedRotatingGroupRequiresPreparedBytes(t *testing.T) {
	original := rotatingOriginal()
	prepared, err := ValidatePreparedRotatingGroup(original, preparedFor(t, original, rotatingTarget, nil))
	if err != nil {
		t.Fatal(err)
	}
	signedHex := func(txns []types.Transaction) []string {
		out := make([]string, len(txns))
		for i, txn := range txns {
			out[i] = hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txn}))
		}
		return out
	}
	if _, err := validateSignedRotatingGroup(prepared, &signerapi.RotatingSignResponse{Signed: signedHex(prepared)}); err != nil {
		t.Fatal(err)
	}
	changed := append([]types.Transaction(nil), prepared...)
	changed[0].Amount = 99
	if _, err := validateSignedRotatingGroup(prepared, &signerapi.RotatingSignResponse{Signed: signedHex(changed)}); err == nil {
		t.Fatal("signed bytes that differ from the preparation were accepted")
	}
	if _, err := validateSignedRotatingGroup(prepared, &signerapi.RotatingSignResponse{Signed: signedHex(prepared[:1])}); err == nil {
		t.Fatal("short signed group accepted")
	}
	if _, err := validateSignedRotatingGroup(prepared, nil); err == nil {
		t.Fatal("nil response accepted")
	}
}

func TestRotatingRetryClassification(t *testing.T) {
	stageChanged := &signerclient.HTTPStatusError{StatusCode: http.StatusConflict, Code: signerapi.ErrCodeRotatingStageChanged, Message: "moved"}
	aged := &signerclient.HTTPStatusError{StatusCode: http.StatusBadRequest, Code: signerapi.ErrCodeBadRequest, Message: "fewer than 10 rounds remain before last valid round 1100"}
	lead := &signerclient.HTTPStatusError{StatusCode: http.StatusBadRequest, Code: signerapi.ErrCodeBadRequest, Message: "first valid round 1003 is more than 2 rounds ahead of the current round 1000"}
	unproven := &signerclient.HTTPStatusError{StatusCode: http.StatusConflict, Code: signerapi.ErrCodeRotatingStageUnproven, Message: "not found yet"}
	other := &signerclient.HTTPStatusError{StatusCode: http.StatusBadRequest, Code: signerapi.ErrCodeBadRequest, Message: "rekey target is not a stage of this account"}
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{fmt.Errorf("wrapped: %w", stageChanged), true},
		{aged, true},
		{lead, true},
		{unproven, false},
		{other, false},
		{errors.New("network"), false},
	} {
		if got := isRotatingRetryable(tc.err); got != tc.want {
			t.Errorf("isRotatingRetryable(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
	if !isAuthorizerMovedRejection(errors.New(`HTTP 400: {"message":"TransactionPool.Remember: transaction X: should have been authorized by A but was actually authorized by B"}`)) {
		t.Fatal("ledger authorizer rejection not recognised")
	}
	if isAuthorizerMovedRejection(errors.New("transaction already in ledger")) {
		t.Fatal("duplicate submission mistaken for an authorizer move")
	}
}

func TestCapRotatingWindowShortensLongWindows(t *testing.T) {
	txn := rotatingOriginal()
	txn.LastValid = txn.FirstValid + 1000
	capRotatingWindow(&txn, nil, false)
	if txn.LastValid != txn.FirstValid+RotatingMaxValidityWindow {
		t.Fatalf("window = %d", txn.LastValid-txn.FirstValid)
	}
	short := rotatingOriginal()
	capRotatingWindow(&short, nil, false)
	if short.LastValid != 1100 {
		t.Fatal("a window within the limit was changed")
	}
}
