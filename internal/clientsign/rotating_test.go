// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientsign

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

var (
	rotatingAccount = types.Address{1}
	rotatingTarget  = types.Address{2}
)

// stubStageProgram stands in for a stage's program. The client cannot derive
// stage addresses, so it checks only that the spend is authorized by a
// program whose address fits the stage; any program serves.
var stubStageProgram = []byte{0x0a, 0x81, 0x01}

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

// preparedFor builds the response an honest signer returns: the spend with
// the rekey and a 3000 microAlgo authorization charge, one resource dummy,
// and the report of exactly those changes. mutate then changes the group
// without touching the report, as a signer that misreports would.
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
	report := &signerapi.MutationReport{
		OriginalCount:  1,
		FinalCount:     len(txns),
		DummiesAdded:   len(dummies),
		GroupIDChanged: true,
		FeesModified:   []int{0},
		TotalFeesDelta: int(spend.Fee - original.Fee),
		Reason:         "lsig_budget",
	}
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
		Mutations: report,
	}
}

func TestValidatePreparedRotatingGroupAcceptsHonestPreparation(t *testing.T) {
	original := rotatingOriginal()
	txns, err := ValidatePreparedRotatingGroup(original, preparedFor(t, original, rotatingTarget, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(txns) != 2 || txns[0].RekeyTo != rotatingTarget || txns[0].Fee != 4000 {
		t.Fatalf("validated group = %d txns, rekey %s, fee %d", len(txns), txns[0].RekeyTo, txns[0].Fee)
	}
}

// A spend that needs no dummies and no charge comes back with no report, and
// then only the rekey may differ. A raise on it must be reported.
func TestValidatePreparedRotatingGroupSingleSpend(t *testing.T) {
	original := rotatingOriginal()
	single := func(fee types.MicroAlgos, report *signerapi.MutationReport) *signerapi.RotatingPrepareResponse {
		spend := original
		spend.RekeyTo = rotatingTarget
		spend.Fee = fee
		return &signerapi.RotatingPrepareResponse{
			Account: original.Sender.String(), Stage: 3, Target: 4, RekeyTo: rotatingTarget.String(),
			Transactions: []string{hex.EncodeToString(txnutil.EncodeWithPrefix(spend))},
			Mutations:    report,
		}
	}
	txns, err := ValidatePreparedRotatingGroup(original, single(original.Fee, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(txns) != 1 || txns[0].RekeyTo != rotatingTarget || txns[0].Fee != original.Fee {
		t.Fatalf("validated group = %d txns, rekey %s, fee %d", len(txns), txns[0].RekeyTo, txns[0].Fee)
	}
	reported := &signerapi.MutationReport{OriginalCount: 1, FinalCount: 1, FeesModified: []int{0}, TotalFeesDelta: 3000}
	if _, err := ValidatePreparedRotatingGroup(original, single(4000, reported)); err != nil {
		t.Fatalf("reported raise refused: %v", err)
	}
	if _, err := ValidatePreparedRotatingGroup(original, single(4000, nil)); err == nil || !strings.Contains(err.Error(), "signer changed unreported fields at original index 0") {
		t.Fatalf("unreported raise: err = %v", err)
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
		}, want: "signer changed unreported fields at original index 0"},
		{name: "changed amount", resp: func() *signerapi.RotatingPrepareResponse {
			return preparedFor(t, original, rotatingTarget, func(tx []types.Transaction) { tx[0].Amount = 8 })
		}, want: "signer changed unreported fields at original index 0"},
		{name: "lowered fee", resp: func() *signerapi.RotatingPrepareResponse {
			return preparedFor(t, original, rotatingTarget, func(tx []types.Transaction) { tx[0].Fee = 10 })
		}, want: "signer lowered the fee"},
		// The audit's case: a raise far above the one the report claims.
		{name: "fee raise larger than reported", resp: func() *signerapi.RotatingPrepareResponse {
			return preparedFor(t, original, rotatingTarget, func(tx []types.Transaction) { tx[0].Fee = 5_000_000 })
		}, want: "mutation total_fees_delta 3000 does not match observed delta 4999000"},
		{name: "fee raise not in the report", resp: func() *signerapi.RotatingPrepareResponse {
			r := preparedFor(t, original, rotatingTarget, nil)
			r.Mutations.FeesModified = nil
			r.Mutations.TotalFeesDelta = 0
			return r
		}, want: "signer changed unreported fields at original index 0"},
		{name: "no mutation report", resp: func() *signerapi.RotatingPrepareResponse {
			r := preparedFor(t, original, rotatingTarget, nil)
			r.Mutations = nil
			return r
		}, want: "signer appended 1 transaction(s) without a mutation report"},
		{name: "report miscounts dummies", resp: func() *signerapi.RotatingPrepareResponse {
			r := preparedFor(t, original, rotatingTarget, nil)
			r.Mutations.DummiesAdded = 2
			return r
		}, want: "mutation dummies_added 2 does not match appended count 1"},
		{name: "report miscounts the group", resp: func() *signerapi.RotatingPrepareResponse {
			r := preparedFor(t, original, rotatingTarget, nil)
			r.Mutations.FinalCount = 3
			return r
		}, want: "mutation final_count 3 does not match returned count 2"},
		{name: "report claims passthrough", resp: func() *signerapi.RotatingPrepareResponse {
			r := preparedFor(t, original, rotatingTarget, nil)
			r.Mutations.PassthroughCount = 1
			return r
		}, want: "rotating prepare returned 1 passthrough transaction(s) for sign-only input"},
		{name: "report omits the group ID change", resp: func() *signerapi.RotatingPrepareResponse {
			r := preparedFor(t, original, rotatingTarget, nil)
			r.Mutations.GroupIDChanged = false
			return r
		}, want: "mutation appended dummies without reporting a group ID change"},
		{name: "non-canonical dummy", resp: func() *signerapi.RotatingPrepareResponse {
			return preparedFor(t, original, rotatingTarget, func(tx []types.Transaction) { tx[1].Note = []byte("x") })
		}, want: "appended transaction at index 1 is not the canonical resource dummy"},
		{name: "rekey to sender", resp: func() *signerapi.RotatingPrepareResponse {
			return preparedFor(t, original, rotatingAccount, nil)
		}, want: "another"},
		{name: "reported rekey differs", resp: func() *signerapi.RotatingPrepareResponse {
			r := preparedFor(t, original, rotatingTarget, nil)
			r.RekeyTo = types.Address{3}.String()
			return r
		}, want: "signer changed unreported fields at original index 0"},
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
		// The last stage has no successor: its Stage+1 would wrap to 0.
		{name: "last stage wraps to stage 0", resp: func() *signerapi.RotatingPrepareResponse {
			r := preparedFor(t, original, rotatingTarget, nil)
			r.Stage, r.Target = math.MaxUint64, 0
			return r
		}, want: "prepared target stage 0 is not the stage after 18446744073709551615"},
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

// signedRotatingFor is the answer an honest signer gives to a sign request
// for prepared: the spend authorized by the stage program, named as its
// signer when the program is not the account itself, the dummies with the
// canonical dummy authorization, and the prepared stage, target and IDs.
func signedRotatingFor(t *testing.T, prep *signerapi.RotatingPrepareResponse, prepared []types.Transaction, lsig types.LogicSig) *signerapi.RotatingSignResponse {
	t.Helper()
	spend := types.SignedTxn{Txn: prepared[0], Lsig: lsig}
	if stageAddr := algocrypto.LogicSigAddress(lsig); stageAddr != prepared[0].Sender {
		spend.AuthAddr = stageAddr
	}
	signed := []string{hex.EncodeToString(msgpack.Encode(spend))}
	dummies, err := signing.SignDummyTransactions(prepared[1:])
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dummies {
		signed = append(signed, hex.EncodeToString(d))
	}
	return &signerapi.RotatingSignResponse{
		Signed:  signed,
		Stage:   prep.Stage,
		Target:  prep.Target,
		TxID:    algocrypto.GetTxID(prepared[0]),
		GroupID: base64.StdEncoding.EncodeToString(prepared[0].Group[:]),
	}
}

func TestValidateSignedRotatingGroupRequiresPreparedBytes(t *testing.T) {
	original := rotatingOriginal()
	prep := preparedFor(t, original, rotatingTarget, nil)
	prepared, err := ValidatePreparedRotatingGroup(original, prep)
	if err != nil {
		t.Fatal(err)
	}
	stage := types.LogicSig{Logic: stubStageProgram}
	honest := func() *signerapi.RotatingSignResponse { return signedRotatingFor(t, prep, prepared, stage) }
	if _, err := validateSignedRotatingGroup(prep, prepared, honest()); err != nil {
		t.Fatal(err)
	}
	encodeSigned := func(stxn types.SignedTxn) string { return hex.EncodeToString(msgpack.Encode(stxn)) }
	stageAddr := algocrypto.LogicSigAddress(stage)

	tests := []struct {
		name   string
		mutate func(*signerapi.RotatingSignResponse)
		want   string
	}{
		{name: "changed spend", mutate: func(r *signerapi.RotatingSignResponse) {
			changed := append([]types.Transaction(nil), prepared...)
			changed[0].Amount = 99
			r.Signed[0] = encodeSigned(types.SignedTxn{Txn: changed[0], Lsig: stage, AuthAddr: stageAddr})
		}, want: "transaction at index 0 differs from the prepared transaction"},
		{name: "short group", mutate: func(r *signerapi.RotatingSignResponse) { r.Signed = r.Signed[:1] },
			want: "signed group has 1 transactions, prepared 2"},
		{name: "other stage reported", mutate: func(r *signerapi.RotatingSignResponse) { r.Stage = 2 },
			want: "signer reports stage 2 to 4, prepared 3 to 4"},
		{name: "other target reported", mutate: func(r *signerapi.RotatingSignResponse) { r.Target = 5 },
			want: "signer reports stage 3 to 5, prepared 3 to 4"},
		{name: "other transaction ID reported", mutate: func(r *signerapi.RotatingSignResponse) { r.TxID = "OTHER" },
			want: "signer reports transaction ID OTHER"},
		{name: "other group ID reported", mutate: func(r *signerapi.RotatingSignResponse) {
			r.GroupID = base64.StdEncoding.EncodeToString(make([]byte, 32))
		}, want: "signer reports group ID"},
		{name: "dummy without the dummy authorization", mutate: func(r *signerapi.RotatingSignResponse) {
			r.Signed[1] = encodeSigned(types.SignedTxn{Txn: prepared[1], Sig: types.Signature{1}})
		}, want: "appended transaction at index 1 does not carry the canonical resource dummy authorization"},
		{name: "spend signed by a key, not a program", mutate: func(r *signerapi.RotatingSignResponse) {
			r.Signed[0] = encodeSigned(types.SignedTxn{Txn: prepared[0], Sig: types.Signature{1}, AuthAddr: stageAddr})
		}, want: "transaction at index 0: spend is not authorized by a stage program"},
		{name: "spend with a second authorization", mutate: func(r *signerapi.RotatingSignResponse) {
			r.Signed[0] = encodeSigned(types.SignedTxn{Txn: prepared[0], Lsig: stage, Sig: types.Signature{1}, AuthAddr: stageAddr})
		}, want: "transaction at index 0: spend carries more than one authorization"},
		{name: "delegated stage program", mutate: func(r *signerapi.RotatingSignResponse) {
			delegated := types.LogicSig{Logic: stubStageProgram, Sig: types.Signature{1}}
			r.Signed[0] = encodeSigned(types.SignedTxn{Txn: prepared[0], Lsig: delegated, AuthAddr: stageAddr})
		}, want: "transaction at index 0: spend's stage program is delegated by a signature"},
		{name: "signer not named", mutate: func(r *signerapi.RotatingSignResponse) {
			r.Signed[0] = encodeSigned(types.SignedTxn{Txn: prepared[0], Lsig: stage})
		}, want: "transaction at index 0: spend does not name its signer " + stageAddr.String()},
		{name: "other signer named", mutate: func(r *signerapi.RotatingSignResponse) {
			r.Signed[0] = encodeSigned(types.SignedTxn{Txn: prepared[0], Lsig: stage, AuthAddr: types.Address{7}})
		}, want: "transaction at index 0: spend names signer " + types.Address{7}.String() + ", not its stage program's address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := honest()
			tt.mutate(resp)
			_, err := validateSignedRotatingGroup(prep, prepared, resp)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}

	// A response element carrying a second transaction after the prepared
	// one would reach the node as two transactions.
	extra := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: rotatingAccount, Fee: 1000, FirstValid: 1000, LastValid: 1100, GenesisHash: types.Digest{9}}, PaymentTxnFields: types.PaymentTxnFields{Receiver: types.Address{8}, Amount: 1_000_000}}
	trailing := honest()
	trailing.Signed[0] += hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: extra}))
	if _, err := validateSignedRotatingGroup(prep, prepared, trailing); !errors.Is(err, canonical.ErrNotCanonical) || !strings.HasPrefix(err.Error(), "transaction at index 0: ") {
		t.Fatalf("trailing transaction accepted: %v", err)
	}
	if _, err := validateSignedRotatingGroup(prep, prepared, nil); err == nil {
		t.Fatal("nil response accepted")
	}
}

// The spend's program must fit the prepared stage: the account itself only
// at stage 0, and never the next stage, which is the rekey target.
func TestValidateSignedRotatingGroupChecksTheStageProgram(t *testing.T) {
	original := rotatingOriginal()
	stage := types.LogicSig{Logic: stubStageProgram}
	stageAddr := algocrypto.LogicSigAddress(stage)

	nextStage := preparedFor(t, original, stageAddr, nil)
	prepared, err := ValidatePreparedRotatingGroup(original, nextStage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateSignedRotatingGroup(nextStage, prepared, signedRotatingFor(t, nextStage, prepared, stage)); err == nil || !strings.Contains(err.Error(), "spend is authorized by the next stage's program") {
		t.Fatalf("spend signed by the next stage: err = %v", err)
	}

	// Every account's first spend: stage 0 is the account itself, so the
	// program's address is the sender and the signed spend names no signer.
	fresh := original
	fresh.Sender = stageAddr
	first := preparedFor(t, fresh, rotatingTarget, nil)
	first.Stage, first.Target = 0, 1
	prepared, err = ValidatePreparedRotatingGroup(fresh, first)
	if err != nil {
		t.Fatal(err)
	}
	honestFirst := signedRotatingFor(t, first, prepared, stage)
	if _, err := validateSignedRotatingGroup(first, prepared, honestFirst); err != nil {
		t.Fatalf("honest stage 0 spend refused: %v", err)
	}
	named := signedRotatingFor(t, first, prepared, stage)
	named.Signed[0] = hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: prepared[0], Lsig: stage, AuthAddr: stageAddr}))
	if _, err := validateSignedRotatingGroup(first, prepared, named); err == nil || !strings.Contains(err.Error(), "spend names signer "+stageAddr.String()+", but at stage 0 the account signs for itself") {
		t.Fatalf("stage 0 spend naming a signer: err = %v", err)
	}

	stageZero := preparedFor(t, original, rotatingTarget, nil)
	stageZero.Stage, stageZero.Target = 0, 1
	prepared, err = ValidatePreparedRotatingGroup(original, stageZero)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateSignedRotatingGroup(stageZero, prepared, signedRotatingFor(t, stageZero, prepared, stage)); err == nil || !strings.Contains(err.Error(), "spend's stage program does not fit stage 0 of the account") {
		t.Fatalf("stage 0 spend signed by another address: err = %v", err)
	}
}

func TestRotatingRetryClassification(t *testing.T) {
	stageChanged := &signerclient.HTTPStatusError{StatusCode: http.StatusConflict, Code: signerapi.ErrCodeRotatingStageChanged, Message: "moved"}
	windowNotCurrent := &signerclient.HTTPStatusError{StatusCode: http.StatusConflict, Code: signerapi.ErrCodeRotatingWindowNotCurrent, Message: "validity window aged during signing; prepare the spend again"}
	// The old timing texts under bad_request: retrying goes by the code, so
	// these are not retried.
	agedText := &signerclient.HTTPStatusError{StatusCode: http.StatusBadRequest, Code: signerapi.ErrCodeBadRequest, Message: "fewer than 10 rounds remain before last valid round 1100"}
	leadText := &signerclient.HTTPStatusError{StatusCode: http.StatusBadRequest, Code: signerapi.ErrCodeBadRequest, Message: "first valid round 1003 is more than 2 rounds ahead of the current round 1000"}
	unproven := &signerclient.HTTPStatusError{StatusCode: http.StatusConflict, Code: signerapi.ErrCodeRotatingStageUnproven, Message: "not found yet"}
	other := &signerclient.HTTPStatusError{StatusCode: http.StatusBadRequest, Code: signerapi.ErrCodeBadRequest, Message: "rekey target is not a stage of this account"}
	for _, tc := range []struct {
		err     error
		want    bool
		summary string
	}{
		{fmt.Errorf("wrapped: %w", stageChanged), true, "the account's authorizer moved"},
		{windowNotCurrent, true, "the validity window is not current"},
		{fmt.Errorf("wrapped: %w", windowNotCurrent), true, "the validity window is not current"},
		{agedText, false, ""},
		{leadText, false, ""},
		{unproven, false, ""},
		{other, false, ""},
		{errors.New("network"), false, ""},
	} {
		if got := isRotatingRetryable(tc.err); got != tc.want {
			t.Errorf("isRotatingRetryable(%v) = %v, want %v", tc.err, got, tc.want)
		}
		if tc.summary != "" {
			if got := rotatingRefusalSummary(tc.err); got != tc.summary {
				t.Errorf("rotatingRefusalSummary(%v) = %q, want %q", tc.err, got, tc.summary)
			}
		}
	}
	// A refusal that is not one of the two retryable codes is summarized by
	// its own text, not assumed to be a timing one.
	if got := rotatingRefusalSummary(other); got != other.Error() {
		t.Errorf("rotatingRefusalSummary(other) = %q, want the error text", got)
	}
	if !isAuthorizerMovedRejection(errors.New(`HTTP 400: {"message":"TransactionPool.Remember: transaction X: should have been authorized by A but was actually authorized by B"}`)) {
		t.Fatal("ledger authorizer rejection not recognised")
	}
	if isAuthorizerMovedRejection(errors.New("transaction already in ledger")) {
		t.Fatal("duplicate submission mistaken for an authorizer move")
	}
}

// Only a ledger that expects the spend's own rekey target means another
// release from the same stage landed first; any other expected authorizer is
// reported as it is.
func TestAuthorizerMovedSummary(t *testing.T) {
	stageAddr := algocrypto.LogicSigAddress(types.LogicSig{Logic: stubStageProgram})
	rejection := func(expected types.Address) error {
		return fmt.Errorf(`failed to submit transaction group: HTTP 400: {"message":"TransactionPool.Remember: transaction X: should have been authorized by %s but was actually authorized by %s"}`, expected, stageAddr)
	}
	if got, want := authorizerMovedSummary(rejection(rotatingTarget), rotatingTarget), "the account rotated under this transaction (another release from the same stage landed first); prepare again"; got != want {
		t.Errorf("rotated: summary = %q, want %q", got, want)
	}
	later := types.Address{8}
	if got, want := authorizerMovedSummary(rejection(later), rotatingTarget), "the ledger expects the account's authorizer to be "+later.String()+", not the stage program that signed this spend"; got != want {
		t.Errorf("other authorizer: summary = %q, want %q", got, want)
	}
	garbled := errors.New("transaction X: should have been authorized by someone but was actually authorized by B")
	if !isAuthorizerMovedRejection(garbled) {
		t.Fatal("garbled rejection not recognised")
	}
	if got, want := authorizerMovedSummary(garbled, rotatingTarget), "the ledger refused the stage program that signed this spend as the account's authorizer"; got != want {
		t.Errorf("unreadable authorizer: summary = %q, want %q", got, want)
	}
	// Recognising the rejection and reading its address ignore case alike.
	for _, msg := range []string{
		strings.ToUpper(rejection(rotatingTarget).Error()),
		strings.ToLower(rejection(rotatingTarget).Error()),
	} {
		err := errors.New(msg)
		if !isAuthorizerMovedRejection(err) {
			t.Errorf("rejection not recognised: %q", msg)
		}
		if got, ok := ledgerExpectedAuthorizer(err); !ok || got != rotatingTarget {
			t.Errorf("expected authorizer from %q = %s, %v; want %s", msg, got, ok, rotatingTarget)
		}
	}
}

func TestCapRotatingWindowShortensLongWindows(t *testing.T) {
	txn := rotatingOriginal()
	txn.LastValid = txn.FirstValid + 1000
	var out bytes.Buffer
	capRotatingWindow(&txn, &out)
	if txn.LastValid != txn.FirstValid+rotatingkey.RotatingMaxValidityWindow {
		t.Fatalf("window = %d", txn.LastValid-txn.FirstValid)
	}
	if got, want := out.String(), fmt.Sprintf("  Validity window shortened to %d rounds for the rotating account\n", rotatingkey.RotatingMaxValidityWindow); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
	short := rotatingOriginal()
	out.Reset()
	capRotatingWindow(&short, &out)
	if short.LastValid != 1100 {
		t.Fatal("a window within the limit was changed")
	}
	if out.Len() != 0 {
		t.Fatalf("a window within the limit was reported: %q", out.String())
	}
}

// fakeAlgod serves the status, suggested-params and simulate endpoints the
// rotating flow reads before signing.
func fakeAlgod(t *testing.T, round uint64, simulated *[]types.Transaction) *algod.Client {
	return fakeAlgodWithSubmit(t, round, simulated, nil)
}

// fakeAlgodWithSubmit is fakeAlgod that also serves submission: submit gets
// the raw bytes posted and writes the answer.
func fakeAlgodWithSubmit(t *testing.T, round uint64, simulated *[]types.Transaction, submit func(http.ResponseWriter, []byte)) *algod.Client {
	t.Helper()
	genesis := types.Digest{9}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2/status":
			_ = json.NewEncoder(w).Encode(models.NodeStatus{LastRound: round})
		case "/v2/transactions/params":
			_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
				LastRound: round, Fee: 0, MinFee: 1000, GenesisId: "testnet-v1.0",
				GenesisHash: []byte(base64.StdEncoding.EncodeToString(genesis[:])), ConsensusVersion: "test",
			})
		case "/v2/transactions/simulate":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read simulate request: %v", err)
			}
			var req models.SimulateRequest
			if err := msgpack.Decode(body, &req); err != nil {
				t.Errorf("decode simulate request: %v", err)
			}
			for _, g := range req.TxnGroups {
				for _, s := range g.Txns {
					*simulated = append(*simulated, s.Txn)
				}
			}
			results := make([]models.SimulateTransactionResult, len(*simulated))
			_ = json.NewEncoder(w).Encode(models.SimulateResponse{
				LastRound: round, TxnGroups: []models.SimulateTransactionGroupResult{{TxnResults: results}},
			})
		case "/v2/transactions":
			if submit == nil {
				t.Errorf("unexpected submission")
				w.WriteHeader(http.StatusNotFound)
				return
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read submission: %v", err)
			}
			submit(w, body)
		default:
			t.Errorf("unexpected algod path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client, err := algod.MakeClient(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// rotatingSigner serves prepare with preparedFor and, when sign is set, the
// sign step with it: sign gets the prepare response it answered and the
// prepared group as sent back, and returns the HTTP status and body.
func rotatingSigner(t *testing.T, prepareSeen *types.Transaction, sign func(*signerapi.RotatingPrepareResponse, []types.Transaction) (int, any)) *signerclient.Client {
	t.Helper()
	var prep *signerapi.RotatingPrepareResponse
	signerClient := signerclient.NewSignerClient("http://signer.test")
	signerClient.Client = &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/sign/rotating/prepare":
			var req signerapi.RotatingPrepareRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode prepare request: %v", err)
			}
			group, err := canonical.DecodeGroupHex([]string{req.TxnBytesHex})
			if err != nil {
				t.Errorf("decode prepare transaction: %v", err)
				return jsonResponse(r, http.StatusBadRequest, map[string]string{"error": err.Error()})
			}
			*prepareSeen = group.Entries[0].Txn
			prep = preparedFor(t, *prepareSeen, rotatingTarget, nil)
			return jsonResponse(r, http.StatusOK, prep)
		case "/sign/rotating/sign":
			if sign == nil {
				t.Errorf("unexpected sign request")
				return jsonResponse(r, http.StatusNotFound, map[string]string{"error": "not found"})
			}
			var req signerapi.RotatingSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode sign request: %v", err)
			}
			group, err := canonical.DecodeGroupHex(req.Transactions)
			if err != nil {
				t.Errorf("decode sign request group: %v", err)
				return jsonResponse(r, http.StatusBadRequest, map[string]string{"error": err.Error()})
			}
			txns := make([]types.Transaction, len(group.Entries))
			for i, e := range group.Entries {
				txns[i] = e.Txn
			}
			status, body := sign(prep, txns)
			return jsonResponse(r, status, body)
		}
		return jsonResponse(r, http.StatusNotFound, map[string]string{"error": "not found"})
	})}
	return signerClient
}

// TestSignAndSubmitRotatingRefreshesAgedWindowAndDefaultsContext sends a
// transaction whose validity window expired, with no context in the options.
// The window must be rebuilt from the current round before the signer sees
// it, and the flow must run to the unsigned simulation without a context.
// The rebuild and the signer's fee raise are reported without verbose.
func TestSignAndSubmitRotatingRefreshesAgedWindowAndDefaultsContext(t *testing.T) {
	const round = 5000
	var prepareSeen types.Transaction
	signerClient := rotatingSigner(t, &prepareSeen, nil)
	var simulated []types.Transaction
	algodClient := fakeAlgod(t, round, &simulated)

	txn := rotatingOriginal() // valid 1000-1100: long expired at round 5000
	var out bytes.Buffer
	txIDs, prepared, err := SignAndSubmitRotating(txn, signerClient, algodClient, RotatingOptions{SubmitOptions: SubmitOptions{Simulate: true, Out: &out}})
	if err != nil {
		t.Fatal(err)
	}
	if prepareSeen.FirstValid != round || prepareSeen.LastValid != round+100 {
		t.Fatalf("signer saw validity %d-%d, want %d-%d", prepareSeen.FirstValid, prepareSeen.LastValid, round, round+100)
	}
	if prepareSeen.Receiver != txn.Receiver || prepareSeen.Amount != txn.Amount {
		t.Fatal("refreshing the window changed other fields")
	}
	if len(txIDs) != 2 || len(prepared) != 2 || len(simulated) != 2 {
		t.Fatalf("simulated %d txns, prepared %d, ids %d; want 2 each", len(simulated), len(prepared), len(txIDs))
	}
	for _, want := range []string{
		"  Validity window has aged (rounds 1000-1100); rebuilding it from the current round\n",
		"  Signer raised the spend's fee by 3000 microAlgos for authorization (fee now 4000 microAlgos)\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output = %q, want %q", out.String(), want)
		}
	}
}

// TestSignAndSubmitRotatingSubmitsCheckedSignedGroup runs the whole flow: the
// signed group is checked against the prepared one and submitted exactly as
// returned; a signed group that misreports its stage is never submitted; and
// a ledger refusal that names the spend's own rekey target is reported as
// another release from the same stage landing first.
func TestSignAndSubmitRotatingSubmitsCheckedSignedGroup(t *testing.T) {
	const round = 1000
	stage := types.LogicSig{Logic: stubStageProgram}
	run := func(t *testing.T, sign func(*signerapi.RotatingPrepareResponse, []types.Transaction) *signerapi.RotatingSignResponse, submit func(http.ResponseWriter, []byte)) (*signerapi.RotatingSignResponse, error) {
		t.Helper()
		var prepareSeen types.Transaction
		var answered *signerapi.RotatingSignResponse
		signerClient := rotatingSigner(t, &prepareSeen, func(prep *signerapi.RotatingPrepareResponse, txns []types.Transaction) (int, any) {
			answered = sign(prep, txns)
			return http.StatusOK, answered
		})
		var simulated []types.Transaction
		algodClient := fakeAlgodWithSubmit(t, round, &simulated, submit)
		_, _, err := SignAndSubmitRotating(rotatingOriginal(), signerClient, algodClient, RotatingOptions{SubmitOptions: SubmitOptions{Out: io.Discard}})
		return answered, err
	}
	honest := func(prep *signerapi.RotatingPrepareResponse, txns []types.Transaction) *signerapi.RotatingSignResponse {
		return signedRotatingFor(t, prep, txns, stage)
	}

	t.Run("submits the signed bytes", func(t *testing.T) {
		var submitted []byte
		answered, err := run(t, honest, func(w http.ResponseWriter, body []byte) {
			submitted = body
			_ = json.NewEncoder(w).Encode(map[string]string{"txId": "TXID"})
		})
		if err != nil {
			t.Fatal(err)
		}
		var want []byte
		for _, h := range answered.Signed {
			raw, err := hex.DecodeString(h)
			if err != nil {
				t.Fatal(err)
			}
			want = append(want, raw...)
		}
		if !bytes.Equal(submitted, want) {
			t.Fatal("algod did not receive the signed group exactly as returned")
		}
	})

	// A submit call that gets no answer keeps its outcome, and the signed
	// group's IDs, through the rotating flow's wrapping.
	t.Run("keeps a lost submission's outcome", func(t *testing.T) {
		answered, err := run(t, honest, func(w http.ResponseWriter, _ []byte) {
			if conn, _, hijackErr := w.(http.Hijacker).Hijack(); hijackErr == nil {
				_ = conn.Close()
			}
		})
		var failure *signing.SubmissionError
		if !errors.As(err, &failure) || failure.State != signing.SubmissionUnknown {
			t.Fatalf("err = %v, want an unknown submission outcome", err)
		}
		if len(failure.TxIDs) != len(answered.Signed) || failure.TxIDs[0] != answered.TxID {
			t.Fatalf("TxIDs = %v, want the %d signed transactions, %s first", failure.TxIDs, len(answered.Signed), answered.TxID)
		}
		if !strings.HasPrefix(err.Error(), "submit rotating spend "+answered.TxID+": failed to submit transaction") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("refuses a misreported stage before submitting", func(t *testing.T) {
		_, err := run(t, func(prep *signerapi.RotatingPrepareResponse, txns []types.Transaction) *signerapi.RotatingSignResponse {
			resp := honest(prep, txns)
			resp.Stage = prep.Stage + 1
			return resp
		}, nil)
		if err == nil || !strings.Contains(err.Error(), "verify signer response: signer reports stage 4 to 4, prepared 3 to 4") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("reports a rotation under the spend", func(t *testing.T) {
		stageAddr := algocrypto.LogicSigAddress(stage)
		_, err := run(t, honest, func(w http.ResponseWriter, _ []byte) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message": fmt.Sprintf("TransactionPool.Remember: transaction X: should have been authorized by %s but was actually authorized by %s", rotatingTarget, stageAddr),
			})
		})
		if err == nil || !strings.Contains(err.Error(), "the account rotated under this transaction (another release from the same stage landed first); prepare again: ") {
			t.Fatalf("err = %v", err)
		}
	})

	// Any other authorizer is reported as it is, without advice to prepare
	// again, which the client cannot tell would help.
	t.Run("reports another authorizer without advice", func(t *testing.T) {
		stageAddr := algocrypto.LogicSigAddress(stage)
		other := types.Address{8}
		_, err := run(t, honest, func(w http.ResponseWriter, _ []byte) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message": fmt.Sprintf("TransactionPool.Remember: transaction X: should have been authorized by %s but was actually authorized by %s", other, stageAddr),
			})
		})
		if err == nil || !strings.Contains(err.Error(), "the ledger expects the account's authorizer to be "+other.String()+", not the stage program that signed this spend: ") {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(err.Error(), "prepare again") {
			t.Fatalf("err = %v, advises preparing again", err)
		}
	})
}

// TestSignAndSubmitRotatingRetries follows the SDK's retry rule. A
// rotating_stage_changed refusal prepares the same transaction again, its
// window rebuilt only if no longer current. A rotating_window_not_current
// refusal rebuilds the window from the current round at the maximum width and
// says so. Either way the fee notice for the same raise is shown once, only
// the attempt that is signed is submitted, and the caller's transaction is
// left as it was.
func TestSignAndSubmitRotatingRetries(t *testing.T) {
	const round = 1000
	stage := types.LogicSig{Logic: stubStageProgram}
	refusal := map[string]signerapi.ErrorResponse{
		signerapi.ErrCodeRotatingStageChanged:     {Error: "the account's authorizer changed before signing", Code: signerapi.ErrCodeRotatingStageChanged},
		signerapi.ErrCodeRotatingWindowNotCurrent: {Error: "fewer than 10 rounds remain before last valid round", Code: signerapi.ErrCodeRotatingWindowNotCurrent},
	}
	// run sends txn; the first refusals sign requests are refused with code,
	// the rest signed. It returns the spends presented for signing, the
	// output, the number of submissions and the error.
	run := func(t *testing.T, txn types.Transaction, code string, refusals int) ([]types.Transaction, string, int, error) {
		t.Helper()
		var spends []types.Transaction
		var prepareSeen types.Transaction
		signerClient := rotatingSigner(t, &prepareSeen, func(prep *signerapi.RotatingPrepareResponse, txns []types.Transaction) (int, any) {
			spends = append(spends, txns[0])
			if len(spends) <= refusals {
				return http.StatusConflict, refusal[code]
			}
			return http.StatusOK, signedRotatingFor(t, prep, txns, stage)
		})
		var simulated []types.Transaction
		submits := 0
		algodClient := fakeAlgodWithSubmit(t, round, &simulated, func(w http.ResponseWriter, _ []byte) {
			submits++
			_ = json.NewEncoder(w).Encode(map[string]string{"txId": "TXID"})
		})
		caller := txn
		before := txnutil.EncodeWithPrefix(caller)
		var out bytes.Buffer
		_, _, err := SignAndSubmitRotating(caller, signerClient, algodClient, RotatingOptions{SubmitOptions: SubmitOptions{Out: &out}})
		if !bytes.Equal(txnutil.EncodeWithPrefix(caller), before) {
			t.Fatal("the caller's transaction was modified")
		}
		return spends, out.String(), submits, err
	}
	window := func(txn types.Transaction) string { return fmt.Sprintf("%d-%d", txn.FirstValid, txn.LastValid) }
	feeNotice := "  Signer raised the spend's fee by 3000 microAlgos for authorization (fee now 4000 microAlgos)\n"

	t.Run("stage changed prepares the same transaction again", func(t *testing.T) {
		txn := rotatingOriginal()
		txn.FirstValid, txn.LastValid = 999, 1049 // current at round 1000
		spends, out, submits, err := run(t, txn, signerapi.ErrCodeRotatingStageChanged, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(spends) != 2 || submits != 1 {
			t.Fatalf("sign requests = %d, submissions = %d; want 2 and 1", len(spends), submits)
		}
		for i, spend := range spends {
			if got := window(spend); got != "999-1049" {
				t.Fatalf("attempt %d presented rounds %s, want the unchanged 999-1049", i+1, got)
			}
		}
		if !strings.Contains(out, "  Signer refused and released no signature (the account's authorizer moved); preparing the transaction again (attempt 2 of 3)\n") {
			t.Fatalf("output = %q, want the retry", out)
		}
		if got := strings.Count(out, feeNotice); got != 1 {
			t.Fatalf("fee notice shown %d times, want once: %q", got, out)
		}
	})

	t.Run("window not current is rebuilt at the maximum width", func(t *testing.T) {
		txn := rotatingOriginal()
		txn.FirstValid, txn.LastValid = 1000, 1020 // a 20-round window
		spends, out, submits, err := run(t, txn, signerapi.ErrCodeRotatingWindowNotCurrent, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(spends) != 2 || submits != 1 {
			t.Fatalf("sign requests = %d, submissions = %d; want 2 and 1", len(spends), submits)
		}
		if got := window(spends[0]); got != "1000-1020" {
			t.Fatalf("first attempt presented rounds %s, want 1000-1020", got)
		}
		if got, want := window(spends[1]), fmt.Sprintf("1000-%d", 1000+rotatingkey.RotatingMaxValidityWindow); got != want {
			t.Fatalf("retry presented rounds %s, want %s", got, want)
		}
		if want := "  Signer found the validity window (rounds 1000-1020) no longer current and released no signature; widened it to the maximum 100 rounds from the current round (rounds 1000-1100) (attempt 2 of 3)\n"; !strings.Contains(out, want) {
			t.Fatalf("output = %q, want %q", out, want)
		}
		if got := strings.Count(out, feeNotice); got != 1 {
			t.Fatalf("fee notice shown %d times, want once: %q", got, out)
		}
	})

	t.Run("a full-width window is rebuilt, not widened", func(t *testing.T) {
		spends, out, _, err := run(t, rotatingOriginal(), signerapi.ErrCodeRotatingWindowNotCurrent, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(spends) != 2 {
			t.Fatalf("sign requests = %d, want 2", len(spends))
		}
		if want := "  Signer found the validity window (rounds 1000-1100) no longer current and released no signature; rebuilt it at the maximum 100 rounds from the current round (rounds 1000-1100) (attempt 2 of 3)\n"; !strings.Contains(out, want) {
			t.Fatalf("output = %q, want %q", out, want)
		}
	})

	t.Run("the last attempt's refusal is returned", func(t *testing.T) {
		spends, out, submits, err := run(t, rotatingOriginal(), signerapi.ErrCodeRotatingWindowNotCurrent, rotatingRetryAttempts)
		if !hasRotatingRefusalCode(err, signerapi.ErrCodeRotatingWindowNotCurrent) {
			t.Fatalf("err = %v, want the window refusal", err)
		}
		if len(spends) != rotatingRetryAttempts || submits != 0 {
			t.Fatalf("sign requests = %d, submissions = %d; want %d and 0", len(spends), submits, rotatingRetryAttempts)
		}
		if got := strings.Count(out, "no longer current and released no signature"); got != rotatingRetryAttempts-1 {
			t.Fatalf("window rebuilt %d times, want %d: %q", got, rotatingRetryAttempts-1, out)
		}
	})
}

func TestFreshenRotatingValidityKeepsCurrentWindows(t *testing.T) {
	var simulated []types.Transaction
	algodClient := fakeAlgod(t, 1000, &simulated)
	txn := rotatingOriginal()
	fresh, note, err := freshenRotatingValidity(context.Background(), txn, algodClient)
	if err != nil {
		t.Fatal(err)
	}
	if note != "" || fresh.FirstValid != txn.FirstValid || fresh.LastValid != txn.LastValid {
		t.Fatalf("a current window was rebuilt (note %q)", note)
	}
	aged := txn
	aged.FirstValid, aged.LastValid = 950, 1000+rotatingkey.RotatingMinRemaining-1
	if fresh, note, err = freshenRotatingValidity(context.Background(), aged, algodClient); err != nil || note != "Validity window has aged (rounds 950-1009); rebuilding it from the current round" {
		t.Fatalf("window with too few rounds left: note=%q err=%v", note, err)
	}
	if fresh.FirstValid != 1000 || fresh.LastValid != 1059 {
		t.Fatalf("aged window rebuilt as %d-%d, want its width kept at 1000-1059", fresh.FirstValid, fresh.LastValid)
	}
	// A fresh window narrower than the rounds that must remain at signing
	// could never be signed: it is not called aged, and is rebuilt wide.
	narrow := txn
	narrow.LastValid = 1005
	want := fmt.Sprintf("Validity window (rounds 1000-1005) spans 5 rounds, fewer than the %d a rotating account needs left when it signs; rebuilding it from the current round with %d rounds", rotatingkey.RotatingMinRemaining, rotatingkey.RotatingMaxValidityWindow)
	if fresh, note, err = freshenRotatingValidity(context.Background(), narrow, algodClient); err != nil || note != want {
		t.Fatalf("narrow window: note=%q err=%v, want %q", note, err, want)
	}
	if fresh.FirstValid != 1000 || fresh.LastValid != 1000+rotatingkey.RotatingMaxValidityWindow {
		t.Fatalf("narrow window rebuilt as %d-%d", fresh.FirstValid, fresh.LastValid)
	}
	// A window that starts in the future has not aged: the note says where
	// it starts.
	early := txn
	early.FirstValid = 1000 + rotatingkey.RotatingMaxLead + 1
	early.LastValid = early.FirstValid + 50
	want = fmt.Sprintf("Validity window (rounds 1003-1053) starts 3 rounds ahead of the current round 1000, more than the %d a rotating account signs; rebuilding it from the current round", rotatingkey.RotatingMaxLead)
	if _, note, err = freshenRotatingValidity(context.Background(), early, algodClient); err != nil || note != want {
		t.Fatalf("window too far ahead: note=%q err=%v, want %q", note, err, want)
	}
}

// A rebuilt window keeps its width unless that could never be signed or is
// over the limit; widened, as after the signer's rotating_window_not_current
// refusal, it always gets the maximum. Both are the SDK's refresh rule.
func TestRefreshRotatingValidityWidth(t *testing.T) {
	var simulated []types.Transaction
	algodClient := fakeAlgod(t, 2000, &simulated)
	for _, tc := range []struct {
		first, last types.Round
		want        types.Round
	}{
		{1000, 1050, 50},
		{1000, 1000 + rotatingkey.RotatingMinRemaining, rotatingkey.RotatingMinRemaining},
		{1000, 1000 + rotatingkey.RotatingMinRemaining - 1, rotatingkey.RotatingMaxValidityWindow},
		{1000, 1000, rotatingkey.RotatingMaxValidityWindow},
		{1000, 1500, rotatingkey.RotatingMaxValidityWindow},
		{1000, 900, rotatingkey.RotatingMaxValidityWindow},
	} {
		txn := rotatingOriginal()
		txn.FirstValid, txn.LastValid = tc.first, tc.last
		fresh, err := refreshRotatingValidity(context.Background(), txn, algodClient, false)
		if err != nil {
			t.Fatal(err)
		}
		if fresh.FirstValid != 2000 || fresh.LastValid != 2000+tc.want {
			t.Errorf("window %d-%d rebuilt as %d-%d, want 2000-%d", tc.first, tc.last, fresh.FirstValid, fresh.LastValid, 2000+tc.want)
		}
		// Widened, every window gets the maximum.
		widened, err := refreshRotatingValidity(context.Background(), txn, algodClient, true)
		if err != nil {
			t.Fatal(err)
		}
		if widened.FirstValid != 2000 || widened.LastValid != 2000+rotatingkey.RotatingMaxValidityWindow {
			t.Errorf("window %d-%d widened as %d-%d, want 2000-%d", tc.first, tc.last, widened.FirstValid, widened.LastValid, 2000+rotatingkey.RotatingMaxValidityWindow)
		}
	}
}

// TestRotatingSignRequestCarriesAppCallInfo checks that the sign request
// sends the prepared group unchanged and forwards the spend's app-call
// metadata, which the signer renders in the approval prompt.
func TestRotatingSignRequestCarriesAppCallInfo(t *testing.T) {
	prep := &signerapi.RotatingPrepareResponse{Transactions: []string{"5458aa", "5458bb"}}
	info := &signerapi.AppCallInfo{Mode: "abi", Method: "withdraw(uint64)void"}
	req := rotatingSignRequest("ACCOUNT", prep, SubmitOptions{AppCallInfo: []*signerapi.AppCallInfo{info}})
	if req.Account != "ACCOUNT" || len(req.Transactions) != 2 || req.Transactions[0] != "5458aa" || req.Transactions[1] != "5458bb" {
		t.Fatalf("sign request does not carry the prepared group unchanged: %+v", req)
	}
	if req.AppCallInfo != info {
		t.Fatalf("app-call info = %+v, want the spend's", req.AppCallInfo)
	}
	if got := rotatingSignRequest("ACCOUNT", prep, SubmitOptions{}).AppCallInfo; got != nil {
		t.Fatalf("app-call info without options = %+v, want none", got)
	}
}
