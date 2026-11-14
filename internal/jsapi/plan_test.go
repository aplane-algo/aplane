// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	algoCrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/dop251/goja"

	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// planTestGenesisID names the network the fake algod of planTestAPI serves;
// planTestTxn builds for it, since plan() refuses another network's.
const planTestGenesisID = "plan-test"

func planTestTxn(t *testing.T, note string) types.Transaction {
	t.Helper()
	sender := algoCrypto.GenerateAccount().Address
	return types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{Sender: sender, Fee: 1000, FirstValid: 1, LastValid: 1001,
			GenesisID: planTestGenesisID, Note: []byte(note)},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: sender},
	}
}

// planRegroup sets the group ID over txns, as the planner does for a group
// of more than one transaction.
func planRegroup(t *testing.T, txns []types.Transaction) {
	t.Helper()
	if len(txns) < 2 {
		return
	}
	for i := range txns {
		txns[i].Group = types.Digest{}
	}
	gid, err := algoCrypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatal(err)
	}
	for i := range txns {
		txns[i].Group = gid
	}
}

// planGroup builds the plan the signer's planner makes of drafts: each fee
// in raises raised by its amount, dummies canonical resource dummies
// appended, and the group ID over the final group. The report counts the
// request's foreign and passthrough positions as given.
func planGroup(t *testing.T, drafts []types.Transaction, raises map[int]uint64, dummies, foreign, passthrough int) ([]types.Transaction, *signerapi.MutationReport) {
	t.Helper()
	planned := append([]types.Transaction(nil), drafts...)
	report := &signerapi.MutationReport{
		OriginalCount: len(drafts), DummiesAdded: dummies,
		ForeignCount: foreign, PassthroughCount: passthrough,
	}
	for i := range drafts {
		if raise, ok := raises[i]; ok {
			planned[i].Fee += types.MicroAlgos(raise)
			report.FeesModified = append(report.FeesModified, i)
			report.TotalFeesDelta += int(raise)
		}
	}
	if dummies > 0 {
		first := drafts[0]
		extra, err := signing.CreateDummyTransactions(dummies, types.SuggestedParams{
			Fee: first.Fee, FirstRoundValid: first.FirstValid, LastRoundValid: first.LastValid,
			GenesisID: first.GenesisID, GenesisHash: first.GenesisHash[:], FlatFee: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		planned = append(planned, extra...)
		report.Reason = "lsig_budget"
	}
	if len(planned) > 1 && (dummies > 0 || len(raises) > 0 || drafts[0].Group == (types.Digest{})) {
		planRegroup(t, planned)
		report.GroupIDChanged = true
	}
	report.FinalCount = len(planned)
	return planned, report
}

func encodePlan(txns []types.Transaction) []string {
	encoded := make([]string, len(txns))
	for i, txn := range txns {
		encoded[i] = txnutil.EncodeWithPrefixHex(txn)
	}
	return encoded
}

// planTestAPI returns a JS runtime whose plan() reaches a fake algod for the
// test network and a fake signer whose /plan answer is answer's, given the
// requests' transactions (a passthrough entry's from its signed bytes).
func planTestAPI(t *testing.T, answer func(drafts []types.Transaction) signerapi.GroupPlanResponse) *goja.Runtime {
	t.Helper()
	eng, vm, _ := newTestAPI(t)
	algodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/transactions/params" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
			ConsensusVersion: string(protocol.ConsensusV42),
			GenesisHash:      make([]byte, 32),
			GenesisId:        planTestGenesisID,
		})
	}))
	t.Cleanup(algodServer.Close)
	algodClient, err := algod.MakeClient(algodServer.URL, "")
	if err != nil {
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	eng.AlgodClient = algodClient

	signerClient := signerclient.NewSignerClient("http://signer.test")
	signerClient.Client = &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/plan" {
			return nil, fmt.Errorf("unexpected signer path %s", r.URL.Path)
		}
		var req signerapi.GroupSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		drafts := make([]types.Transaction, len(req.Requests))
		for i, request := range req.Requests {
			if request.SignedTxnHex != "" {
				raw, err := hex.DecodeString(request.SignedTxnHex)
				if err != nil {
					return nil, err
				}
				var stxn types.SignedTxn
				if err := msgpack.Decode(raw, &stxn); err != nil {
					return nil, err
				}
				drafts[i] = stxn.Txn
				continue
			}
			txn, err := txnutil.DecodePrefixedHex(request.TxnBytesHex)
			if err != nil {
				return nil, err
			}
			drafts[i] = txn
		}
		return jsonResponse(r, http.StatusOK, answer(drafts))
	})}
	eng.Connection.SignerClient = signerClient
	return vm
}

// planScript is a plan() call over requests, returning its result as JSON.
func planScript(t *testing.T, requests []map[string]interface{}) string {
	t.Helper()
	encoded, err := json.Marshal(requests)
	if err != nil {
		t.Fatal(err)
	}
	return "JSON.stringify(plan(" + string(encoded) + "))"
}

// signedPassthroughHex is txn signed, in its canonical encoding, as a
// passthrough plan() request carries it.
func signedPassthroughHex(txn types.Transaction) string {
	return hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txn, Sig: types.Signature{1}}))
}

// A plan the signer made as its planner does reaches the script as the
// signer returned it: its transactions byte for byte and its report.
func TestPlanReturnsACheckedPlanUnchanged(t *testing.T) {
	sign, foreign, pq := planTestTxn(t, "sign"), planTestTxn(t, "foreign"), planTestTxn(t, "pq")
	mixed := []map[string]interface{}{
		{"authAddress": sign.Sender.String(), "txnBytesHex": txnutil.EncodeWithPrefixHex(sign)},
		{"txnBytesHex": txnutil.EncodeWithPrefixHex(foreign),
			"lsigResources": map[string]interface{}{"programBytes": 1804, "argumentBytes": 1423, "maxOpcodeCost": 20000}},
		{"txnBytesHex": txnutil.EncodeWithPrefixHex(pq), "pqScheme": signerapi.PQSchemeFalcon1024},
	}
	single := planTestTxn(t, "single")
	pre := []types.Transaction{planTestTxn(t, "passthrough"), planTestTxn(t, "managed")}
	planRegroup(t, pre)

	for _, tc := range []struct {
		name     string
		requests []map[string]interface{}
		answer   func(t *testing.T, drafts []types.Transaction) ([]types.Transaction, *signerapi.MutationReport)
	}{
		{"fee raise and dummies", mixed, func(t *testing.T, drafts []types.Transaction) ([]types.Transaction, *signerapi.MutationReport) {
			return planGroup(t, drafts, map[int]uint64{0: 3000}, 2, 2, 0)
		}},
		{"fee raise, no dummies", mixed, func(t *testing.T, drafts []types.Transaction) ([]types.Transaction, *signerapi.MutationReport) {
			return planGroup(t, drafts, map[int]uint64{0: 3000}, 0, 2, 0)
		}},
		{"group ID only", mixed, func(t *testing.T, drafts []types.Transaction) ([]types.Transaction, *signerapi.MutationReport) {
			return planGroup(t, drafts, nil, 0, 2, 0)
		}},
		{"single transaction, nothing changed", []map[string]interface{}{
			{"authAddress": single.Sender.String(), "txnBytesHex": txnutil.EncodeWithPrefixHex(single)},
		}, func(t *testing.T, drafts []types.Transaction) ([]types.Transaction, *signerapi.MutationReport) {
			return drafts, nil
		}},
		{"single transaction, fee raised", []map[string]interface{}{
			{"authAddress": single.Sender.String(), "txnBytesHex": txnutil.EncodeWithPrefixHex(single)},
		}, func(t *testing.T, drafts []types.Transaction) ([]types.Transaction, *signerapi.MutationReport) {
			return planGroup(t, drafts, map[int]uint64{0: 2000}, 0, 0, 0)
		}},
		{"pre-grouped with a passthrough, unchanged", []map[string]interface{}{
			{"signedTxnHex": signedPassthroughHex(pre[0])},
			{"authAddress": pre[1].Sender.String(), "txnBytesHex": txnutil.EncodeWithPrefixHex(pre[1])},
		}, func(t *testing.T, drafts []types.Transaction) ([]types.Transaction, *signerapi.MutationReport) {
			return planGroup(t, drafts, nil, 0, 0, 1)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sent signerapi.GroupPlanResponse
			vm := planTestAPI(t, func(drafts []types.Transaction) signerapi.GroupPlanResponse {
				planned, report := tc.answer(t, drafts)
				sent = signerapi.GroupPlanResponse{Transactions: encodePlan(planned), Mutations: report}
				return sent
			})
			value, err := vm.RunString(planScript(t, tc.requests))
			if err != nil {
				t.Fatalf("plan() error = %v", err)
			}
			var got struct {
				Transactions []string               `json:"transactions"`
				Mutations    map[string]interface{} `json:"mutations"`
			}
			if err := json.Unmarshal([]byte(value.String()), &got); err != nil {
				t.Fatalf("decode plan() result %s: %v", value, err)
			}
			if !reflect.DeepEqual(got.Transactions, sent.Transactions) {
				t.Fatalf("transactions = %v, want the signer's %v", got.Transactions, sent.Transactions)
			}
			if sent.Mutations == nil {
				if got.Mutations != nil {
					t.Fatalf("result = %s, want no mutations", value)
				}
				return
			}
			mutations, want := got.Mutations, sent.Mutations
			if mutations["dummiesAdded"] != float64(want.DummiesAdded) || mutations["groupIDChanged"] != want.GroupIDChanged ||
				mutations["totalFeesDelta"] != float64(want.TotalFeesDelta) || mutations["originalCount"] != float64(want.OriginalCount) ||
				mutations["finalCount"] != float64(want.FinalCount) || mutations["foreignCount"] != float64(want.ForeignCount) ||
				mutations["passthroughCount"] != float64(want.PassthroughCount) {
				t.Fatalf("mutations = %v, want the signer's %+v", mutations, want)
			}
		})
	}
}

// A plan that differs from the requests beyond what the planner may change is
// refused: plan() throws with the reason and returns nothing to the script.
func TestPlanRefusesAPlanTheSignerMayNotHaveMade(t *testing.T) {
	sign, foreign := planTestTxn(t, "sign"), planTestTxn(t, "foreign")
	requests := []map[string]interface{}{
		{"authAddress": sign.Sender.String(), "txnBytesHex": txnutil.EncodeWithPrefixHex(sign)},
		{"txnBytesHex": txnutil.EncodeWithPrefixHex(foreign),
			"lsigResources": map[string]interface{}{"programBytes": 1804, "argumentBytes": 1423, "maxOpcodeCost": 20000}},
	}
	pre := []types.Transaction{planTestTxn(t, "passthrough"), planTestTxn(t, "managed")}
	planRegroup(t, pre)
	passthroughRequests := []map[string]interface{}{
		{"signedTxnHex": signedPassthroughHex(pre[0])},
		{"authAddress": pre[1].Sender.String(), "txnBytesHex": txnutil.EncodeWithPrefixHex(pre[1])},
	}
	// valid is the planner's plan of the two requests: a raise on the
	// sign-mode position and one dummy.
	valid := func(t *testing.T, drafts []types.Transaction) ([]types.Transaction, *signerapi.MutationReport) {
		return planGroup(t, drafts, map[int]uint64{0: 2000}, 1, 1, 0)
	}

	for _, tc := range []struct {
		name     string
		requests []map[string]interface{}
		answer   func(t *testing.T, drafts []types.Transaction) signerapi.GroupPlanResponse
		want     string
	}{
		{"a changed field on an original position", requests, func(t *testing.T, drafts []types.Transaction) signerapi.GroupPlanResponse {
			planned, report := valid(t, drafts)
			planned[1].Amount = 5
			planRegroup(t, planned)
			return signerapi.GroupPlanResponse{Transactions: encodePlan(planned), Mutations: report}
		}, "signer changed unreported fields at original index 1"},
		{"a fee change the report does not list", requests, func(t *testing.T, drafts []types.Transaction) signerapi.GroupPlanResponse {
			planned, report := valid(t, drafts)
			report.FeesModified, report.TotalFeesDelta = nil, 0
			return signerapi.GroupPlanResponse{Transactions: encodePlan(planned), Mutations: report}
		}, "signer changed unreported fields at original index 0"},
		{"a total fee delta that does not match", requests, func(t *testing.T, drafts []types.Transaction) signerapi.GroupPlanResponse {
			planned, report := valid(t, drafts)
			report.TotalFeesDelta = 1000
			return signerapi.GroupPlanResponse{Transactions: encodePlan(planned), Mutations: report}
		}, "mutation total_fees_delta 1000 does not match observed delta 2000"},
		{"a wrong group ID", requests, func(t *testing.T, drafts []types.Transaction) signerapi.GroupPlanResponse {
			planned, report := valid(t, drafts)
			for i := range planned {
				planned[i].Group = types.Digest{1}
			}
			return signerapi.GroupPlanResponse{Transactions: encodePlan(planned), Mutations: report}
		}, "does not carry the canonical group ID"},
		{"a dummy that is not the canonical one", requests, func(t *testing.T, drafts []types.Transaction) signerapi.GroupPlanResponse {
			planned, report := valid(t, drafts)
			planned[2].Fee = 1000
			planRegroup(t, planned)
			return signerapi.GroupPlanResponse{Transactions: encodePlan(planned), Mutations: report}
		}, "appended transaction at index 2 is not the canonical resource dummy"},
		{"dummies without a report", requests, func(t *testing.T, drafts []types.Transaction) signerapi.GroupPlanResponse {
			planned, _ := valid(t, drafts)
			return signerapi.GroupPlanResponse{Transactions: encodePlan(planned)}
		}, "signer appended 1 transaction(s) without a mutation report"},
		{"a dummy count that does not match", requests, func(t *testing.T, drafts []types.Transaction) signerapi.GroupPlanResponse {
			planned, report := valid(t, drafts)
			report.DummiesAdded = 2
			return signerapi.GroupPlanResponse{Transactions: encodePlan(planned), Mutations: report}
		}, "mutation dummies_added 2 does not match appended count 1"},
		{"a final count that does not match", requests, func(t *testing.T, drafts []types.Transaction) signerapi.GroupPlanResponse {
			planned, report := valid(t, drafts)
			report.FinalCount = 2
			return signerapi.GroupPlanResponse{Transactions: encodePlan(planned), Mutations: report}
		}, "mutation final_count 2 does not match returned count 3"},
		{"an original count that does not match", requests, func(t *testing.T, drafts []types.Transaction) signerapi.GroupPlanResponse {
			planned, report := valid(t, drafts)
			report.OriginalCount = 3
			return signerapi.GroupPlanResponse{Transactions: encodePlan(planned), Mutations: report}
		}, "mutation original_count 3 does not match request count 2"},
		{"a dropped transaction", requests, func(t *testing.T, drafts []types.Transaction) signerapi.GroupPlanResponse {
			return signerapi.GroupPlanResponse{Transactions: encodePlan(drafts[:1])}
		}, "signer returned 1 transaction(s), want at least 2"},
		{"bytes that are not canonical", requests, func(t *testing.T, drafts []types.Transaction) signerapi.GroupPlanResponse {
			planned, report := valid(t, drafts)
			encoded := encodePlan(planned)
			encoded[1] += "00"
			return signerapi.GroupPlanResponse{Transactions: encoded, Mutations: report}
		}, "planned transaction at index 1: transaction bytes are not canonical"},
		{"bytes that are not hex", requests, func(t *testing.T, drafts []types.Transaction) signerapi.GroupPlanResponse {
			planned, report := valid(t, drafts)
			encoded := encodePlan(planned)
			encoded[0] = "TXabc"
			return signerapi.GroupPlanResponse{Transactions: encoded, Mutations: report}
		}, "planned transaction at index 0: invalid hex"},
		// The signer raises fees only on the positions it signs, so a raise on
		// a foreign or passthrough position is refused even when reported.
		{"a reported fee raise on a foreign position", requests, func(t *testing.T, drafts []types.Transaction) signerapi.GroupPlanResponse {
			planned, report := planGroup(t, drafts, map[int]uint64{0: 2000, 1: 2000}, 1, 1, 0)
			return signerapi.GroupPlanResponse{Transactions: encodePlan(planned), Mutations: report}
		}, "plan changed the fee of foreign slot at index 1 from 1000 to 3000 microAlgos; the signer may raise fees only on the slots it signs"},
		{"a reported fee raise on a passthrough position", passthroughRequests, func(t *testing.T, drafts []types.Transaction) signerapi.GroupPlanResponse {
			planned, report := planGroup(t, drafts, map[int]uint64{0: 2000}, 0, 0, 1)
			return signerapi.GroupPlanResponse{Transactions: encodePlan(planned), Mutations: report}
		}, "plan changed the fee of passthrough slot at index 0 from 1000 to 3000 microAlgos; the signer may raise fees only on the slots it signs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vm := planTestAPI(t, func(drafts []types.Transaction) signerapi.GroupPlanResponse {
				return tc.answer(t, drafts)
			})
			value, err := vm.RunString(planScript(t, tc.requests))
			var exception *goja.Exception
			if !errors.As(err, &exception) {
				t.Fatalf("plan() = %v, %v; want it to throw", value, err)
			}
			got := exception.Value().String()
			if !strings.HasPrefix(got, "plan() error: invalid group plan: ") || !strings.Contains(got, tc.want) {
				t.Fatalf("plan() threw %q, want the plan refused with %q", got, tc.want)
			}
		})
	}
}

// A script can catch the refusal; it is given the reason and no plan.
func TestPlanRefusalCanBeCaught(t *testing.T) {
	sign := planTestTxn(t, "sign")
	vm := planTestAPI(t, func(drafts []types.Transaction) signerapi.GroupPlanResponse {
		planned := append([]types.Transaction(nil), drafts...)
		planned[0].Note = []byte("changed")
		return signerapi.GroupPlanResponse{Transactions: encodePlan(planned)}
	})
	requests := []map[string]interface{}{
		{"authAddress": sign.Sender.String(), "txnBytesHex": txnutil.EncodeWithPrefixHex(sign)},
	}
	encoded, err := json.Marshal(requests)
	if err != nil {
		t.Fatal(err)
	}
	value, err := vm.RunString(`var planned; try { planned = plan(` + string(encoded) + `) } catch (e) { "caught: " + e + " / " + typeof planned }`)
	want := "caught: plan() error: invalid group plan: signer changed unreported fields at original index 0 / undefined"
	if err != nil || value.String() != want {
		t.Fatalf("script = %v (%v), want %q", value, err, want)
	}
}
