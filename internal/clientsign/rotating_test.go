// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientsign

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// preparedFor builds the response an honest signer returns for one
// rotating transaction, after mutate changes the group.
func preparedFor(t *testing.T, original types.Transaction, rekeyTo types.Address, mutate func([]types.Transaction)) *signerapi.RotatingPrepareResponse {
	t.Helper()
	return preparedGroupFor(t, []types.Transaction{original}, 0, rekeyTo, mutate)
}

// preparedGroupFor builds the response an honest signer returns for a
// group whose rotating transaction is original[rotating]: the rekey set, the
// rotating transaction's fee raised and reported, one canonical dummy and
// the group ID; then mutate changes the group before it is grouped.
func preparedGroupFor(t *testing.T, original []types.Transaction, rotating int, rekeyTo types.Address, mutate func([]types.Transaction)) *signerapi.RotatingPrepareResponse {
	t.Helper()
	txns := append([]types.Transaction(nil), original...)
	txns[rotating].RekeyTo = rekeyTo
	raised := types.MicroAlgos(4000)
	delta := int(raised - txns[rotating].Fee)
	txns[rotating].Fee = raised
	first := original[0]
	dummies, err := signing.CreateDummyTransactions(1, types.SuggestedParams{
		Fee: first.Fee, FirstRoundValid: first.FirstValid, LastRoundValid: first.LastValid,
		GenesisID: first.GenesisID, GenesisHash: first.GenesisHash[:], FlatFee: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	txns = append(txns, dummies...)
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
	owned := []int{}
	for i := range original {
		if i != rotating {
			owned = append(owned, i)
		}
	}
	return &signerapi.RotatingPrepareResponse{
		Account: original[rotating].Sender.String(), Stage: 3, Target: 4, RekeyTo: rekeyTo.String(), Transactions: encoded,
		Rotations:    []signerapi.RotationSlot{{Index: rotating, Stage: 3, Target: 4, RekeyTo: rekeyTo.String()}},
		OwnedIndexes: owned,
		Mutations: &signerapi.MutationReport{
			DummiesAdded: 1, GroupIDChanged: true, FeesModified: []int{rotating}, TotalFeesDelta: delta,
			OriginalCount: len(original), FinalCount: len(original) + 1, Reason: "lsig_budget",
		},
	}
}

func TestValidatePreparedRotatingGroupAcceptsHonestPreparation(t *testing.T) {
	original := rotatingOriginal()
	txns, err := ValidatePreparedRotatingGroup([]types.Transaction{original}, 0, preparedFor(t, original, rotatingTarget, nil))
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
			r.Rotations[0].RekeyTo = r.RekeyTo
			return r
		}, want: "other than"},
		{name: "scalar fields disagree with the rotation", resp: func() *signerapi.RotatingPrepareResponse {
			r := preparedFor(t, original, rotatingTarget, nil)
			r.RekeyTo = types.Address{3}.String()
			return r
		}, want: "do not match"},
		{name: "fee raise not reported", resp: func() *signerapi.RotatingPrepareResponse {
			r := preparedFor(t, original, rotatingTarget, nil)
			r.Mutations.FeesModified = nil
			return r
		}, want: "without reporting"},
		{name: "fee delta misreported", resp: func() *signerapi.RotatingPrepareResponse {
			r := preparedFor(t, original, rotatingTarget, nil)
			r.Mutations.TotalFeesDelta++
			return r
		}, want: "total_fees_delta"},
		{name: "no rotation reported", resp: func() *signerapi.RotatingPrepareResponse {
			r := preparedFor(t, original, rotatingTarget, nil)
			r.Rotations = nil
			return r
		}, want: "reports 0 rotations"},
		{name: "wrong account", resp: func() *signerapi.RotatingPrepareResponse {
			r := preparedFor(t, original, rotatingTarget, nil)
			r.Account = types.Address{4}.String()
			return r
		}, want: "not the sender"},
		{name: "target not the next stage", resp: func() *signerapi.RotatingPrepareResponse {
			r := preparedFor(t, original, rotatingTarget, nil)
			r.Target = r.Stage + 2
			r.Rotations[0].Target = r.Target
			return r
		}, want: "not the stage after"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidatePreparedRotatingGroup([]types.Transaction{original}, 0, tt.resp())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateSignedRotatingGroupRequiresPreparedBytes(t *testing.T) {
	original := rotatingOriginal()
	prepared, err := ValidatePreparedRotatingGroup([]types.Transaction{original}, 0, preparedFor(t, original, rotatingTarget, nil))
	if err != nil {
		t.Fatal(err)
	}
	oneRotation := []signerapi.RotationSlot{{Index: 0}}
	signedHex := func(txns []types.Transaction) []string {
		out := make([]string, len(txns))
		for i, txn := range txns {
			out[i] = hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txn}))
		}
		return out
	}
	if _, err := validateSignedRotatingGroup(prepared, 0, &signerapi.RotatingSignResponse{Rotations: oneRotation, Signed: signedHex(prepared)}); err != nil {
		t.Fatal(err)
	}
	changed := append([]types.Transaction(nil), prepared...)
	changed[0].Amount = 99
	if _, err := validateSignedRotatingGroup(prepared, 0, &signerapi.RotatingSignResponse{Rotations: oneRotation, Signed: signedHex(changed)}); err == nil {
		t.Fatal("signed bytes that differ from the preparation were accepted")
	}
	if _, err := validateSignedRotatingGroup(prepared, 0, &signerapi.RotatingSignResponse{Rotations: oneRotation, Signed: signedHex(prepared[:1])}); err == nil {
		t.Fatal("short signed group accepted")
	}
	// A response element carrying a second transaction after the prepared
	// one would reach the node as two transactions.
	honest := signedHex(prepared)
	extra := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: rotatingAccount, Fee: 1000, FirstValid: 1000, LastValid: 1100, GenesisHash: types.Digest{9}}, PaymentTxnFields: types.PaymentTxnFields{Receiver: types.Address{8}, Amount: 1_000_000}}
	trailing := append([]string(nil), honest...)
	trailing[0] = honest[0] + hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: extra}))
	if _, err := validateSignedRotatingGroup(prepared, 0, &signerapi.RotatingSignResponse{Rotations: oneRotation, Signed: trailing}); err == nil || !strings.Contains(err.Error(), "canonically encoded") {
		t.Fatalf("trailing transaction accepted: %v", err)
	}
	if _, err := validateSignedRotatingGroup(prepared, 0, nil); err == nil {
		t.Fatal("nil response accepted")
	}
	if _, err := validateSignedRotatingGroup(prepared, 0, &signerapi.RotatingSignResponse{Signed: honest, Rotations: []signerapi.RotationSlot{{Index: 1}}}); err == nil {
		t.Fatal("a rotation reported at the wrong position was accepted")
	}
	if _, err := validateSignedRotatingGroup(prepared, 0, &signerapi.RotatingSignResponse{Signed: honest, Rotations: oneRotation, Stage: 7}); err == nil {
		t.Fatal("scalar fields disagreeing with the rotation were accepted")
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
	if txn.LastValid != txn.FirstValid+rotatingkey.RotatingMaxValidityWindow {
		t.Fatalf("window = %d", txn.LastValid-txn.FirstValid)
	}
	short := rotatingOriginal()
	capRotatingWindow(&short, nil, false)
	if short.LastValid != 1100 {
		t.Fatal("a window within the limit was changed")
	}
}

// fakeAlgod serves the status, suggested-params and simulate endpoints the
// rotating flow reads before signing.
func fakeAlgod(t *testing.T, round uint64, simulated *[]types.Transaction) *algod.Client {
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

// TestSignAndSubmitRotatingRefreshesAgedWindowAndDefaultsContext sends a
// transaction whose validity window expired, with no context in the options.
// The window must be rebuilt from the current round before the signer sees
// it, and the flow must run to the unsigned simulation without a context.
func TestSignAndSubmitRotatingRefreshesAgedWindowAndDefaultsContext(t *testing.T) {
	const round = 5000
	var prepareSeen types.Transaction
	signerClient := signerclient.NewSignerClient("http://signer.test")
	signerClient.Client = &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/sign/rotating/prepare" {
			return jsonResponse(r, http.StatusNotFound, map[string]string{"error": "not found"})
		}
		var req signerapi.RotatingPrepareRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode prepare request: %v", err)
		}
		if req.TxnBytesHex != "" || len(req.Requests) != 1 {
			t.Errorf("client sent the single-transaction form or %d slots; want the group form with one slot", len(req.Requests))
			return jsonResponse(r, http.StatusBadRequest, map[string]string{"error": "form"})
		}
		group, err := canonical.DecodeGroupHex([]string{req.Requests[0].TxnBytesHex})
		if err != nil {
			t.Errorf("decode prepare transaction: %v", err)
			return jsonResponse(r, http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		prepareSeen = group.Entries[0].Txn
		return jsonResponse(r, http.StatusOK, preparedFor(t, prepareSeen, rotatingTarget, nil))
	})}
	var simulated []types.Transaction
	algodClient := fakeAlgod(t, round, &simulated)

	txn := rotatingOriginal() // valid 1000-1100: long expired at round 5000
	txIDs, prepared, err := SignAndSubmitRotating([]types.Transaction{txn}, 0, nil, signerClient, algodClient, RotatingOptions{SubmitOptions: SubmitOptions{Simulate: true}})
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
}

func TestFreshenRotatingValidityKeepsCurrentWindows(t *testing.T) {
	var simulated []types.Transaction
	algodClient := fakeAlgod(t, 1000, &simulated)
	txn := rotatingOriginal()
	fresh, aged, err := freshenRotatingValidity(context.Background(), txn, algodClient)
	if err != nil {
		t.Fatal(err)
	}
	if aged || fresh.FirstValid != txn.FirstValid || fresh.LastValid != txn.LastValid {
		t.Fatal("a current window was rebuilt")
	}
	nearlyDone := txn
	nearlyDone.LastValid = 1000 + rotatingkey.RotatingMinRemaining - 1
	if _, aged, err = freshenRotatingValidity(context.Background(), nearlyDone, algodClient); err != nil || !aged {
		t.Fatalf("window with too few rounds left: aged=%v err=%v", aged, err)
	}
	early := txn
	early.FirstValid = 1000 + rotatingkey.RotatingMaxLead + 1
	early.LastValid = early.FirstValid + 50
	if _, aged, err = freshenRotatingValidity(context.Background(), early, algodClient); err != nil || !aged {
		t.Fatalf("window too far ahead: aged=%v err=%v", aged, err)
	}
}
