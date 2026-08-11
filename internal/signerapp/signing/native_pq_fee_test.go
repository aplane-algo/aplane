// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/types"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/signerapi"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

func TestApplyNativePQFees(t *testing.T) {
	baseTxn := types.Transaction{Type: types.PaymentTx, Header: types.Header{Fee: 1_000}}
	fnet := PlannerNetworkParams{MinTxnFee: 1_000, ConsensusVersion: string(protocol.ConsensusVFnet5)}

	t.Run("adds only PQ contribution", func(t *testing.T) {
		txns := []types.Transaction{baseTxn}
		delta, indices, err := applyNativePQFees(txns, []authorizationBudget{{pqScheme: nativefalcon.Scheme, mutable: true}}, fnet, false)
		if err != nil {
			t.Fatal(err)
		}
		if delta != 2_000 || uint64(txns[0].Fee) != 3_000 || len(indices) != 1 || indices[0] != 0 {
			t.Fatalf("fee result = delta %d fee %d indices %v, want 2000/3000/[0]", delta, txns[0].Fee, indices)
		}
	})

	t.Run("honors group pooling", func(t *testing.T) {
		txns := []types.Transaction{baseTxn, baseTxn}
		txns[0].Fee = 4_000
		delta, _, err := applyNativePQFees(txns, []authorizationBudget{{mutable: true}, {pqScheme: nativefalcon.Scheme, mutable: true}}, fnet, false)
		if err != nil || delta != 0 {
			t.Fatalf("applyNativePQFees() = delta %d, error %v; want pooled fee accepted", delta, err)
		}
	})

	t.Run("charges v42 oversized note surcharge", func(t *testing.T) {
		txn := baseTxn
		txn.Note = make([]byte, 1_025)
		txns := []types.Transaction{txn}
		delta, _, err := applyNativePQFees(txns, []authorizationBudget{{pqScheme: nativefalcon.Scheme, mutable: true}}, fnet, false)
		if err != nil {
			t.Fatal(err)
		}
		if delta != 2_001 || uint64(txns[0].Fee) != 3_001 {
			t.Fatalf("oversized-note fee = delta %d fee %d, want 2001/3001", delta, txns[0].Fee)
		}
	})

	t.Run("rejects old consensus", func(t *testing.T) {
		txns := []types.Transaction{baseTxn}
		_, _, err := applyNativePQFees(txns, []authorizationBudget{{pqScheme: nativefalcon.Scheme, mutable: true}}, PlannerNetworkParams{MinTxnFee: 1_000, ConsensusVersion: string(protocol.ConsensusV41)}, false)
		if err == nil || !strings.Contains(err.Message, "requires a PQ-capable consensus") {
			t.Fatalf("error = %#v, want consensus rejection", err)
		}
	})

	t.Run("rejects immutable underfunding", func(t *testing.T) {
		txns := []types.Transaction{baseTxn}
		_, _, err := applyNativePQFees(txns, []authorizationBudget{{pqScheme: nativefalcon.Scheme}}, fnet, true)
		if err == nil || !strings.Contains(err.Message, "immutable native PQ group") {
			t.Fatalf("error = %#v, want immutable fee rejection", err)
		}
	})
}

func TestAuthorizationBudgetsRecognizePassthroughPQ(t *testing.T) {
	proof := types.PQSig{Scheme: types.PQScheme{'f', '1'}, PublicKey: []byte{1}, Signature: []byte{2}}
	for _, stxn := range []types.SignedTxn{
		{PQsig: proof},
		{Lsig: types.LogicSig{PQsig: proof}},
	} {
		raw := msgpack.Encode(stxn)
		budgets, err := authorizationBudgets(
			[]signerapi.SignRequest{{SignedTxnHex: hex.EncodeToString(raw)}},
			PlannerIdentitySnapshot{}, map[int]bool{0: true}, map[int]bool{}, map[int][]byte{0: raw},
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(budgets) != 1 || budgets[0].pqScheme != nativefalcon.Scheme {
			t.Fatalf("authorization budget = %#v, want f1", budgets)
		}
	}
}

func TestPlanGroupBudgetsNativeFalconBeforeApproval(t *testing.T) {
	genesisHash := types.Digest{5}
	resolver, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{
		base64.StdEncoding.EncodeToString(genesisHash[:]): "fnet_test",
	})
	if err != nil {
		t.Fatal(err)
	}
	authorizer := types.Address{8}.String()
	txn := types.Transaction{
		Type:   types.PaymentTx,
		Header: types.Header{Sender: types.Address{8}, Fee: 1_000, FirstValid: 1, LastValid: 2, GenesisHash: genesisHash},
	}
	planner := NewPlanner(stubPlannerDeps{
		keyTypes:  map[string]string{authorizer: nativefalcon.KeyType},
		minTxnFee: 1_000, consensusVersion: string(protocol.ConsensusVFnet5),
	}, PlannerOptions{GenesisHashResolver: resolver})
	plan, planErr := planner.PlanGroup("default", signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{
		AuthAddress: authorizer, TxnBytesHex: hex.EncodeToString(msgpack.Encode(txn)),
	}}})
	if planErr != nil {
		t.Fatal(planErr)
	}
	if got := uint64(plan.AllTxns[0].Fee); got != 3_000 {
		t.Fatalf("planned fee = %d, want 3000", got)
	}
	mutations := BuildMutationReport(plan, 1)
	if mutations == nil || mutations.TotalFeesDelta != 2_000 || mutations.Reason != "native_pq_fee" {
		t.Fatalf("mutation report = %#v, want native PQ fee delta", mutations)
	}
	description, _, _ := BuildApprovalDescription(
		signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: authorizer}}},
		plan, plan.AllTxns, func(types.Transaction) string { return "payment" },
	)
	if !strings.Contains(description, "Native Falcon fee adjustment: +2000 microAlgos") {
		t.Fatalf("approval description did not disclose native PQ fee mutation:\n%s", description)
	}
}
