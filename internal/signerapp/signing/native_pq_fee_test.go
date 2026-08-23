// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signerapi"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

func TestApplyGroupFeesNativePQ(t *testing.T) {
	baseTxn := types.Transaction{Type: types.PaymentTx, Header: types.Header{Fee: 1_000}}
	resourcePlan := lsigresource.Plan{TransactionCount: 1, GroupSize: 1}

	t.Run("adds only PQ contribution", func(t *testing.T) {
		txns := []types.Transaction{baseTxn}
		info, err := applyGroupFees(txns, []authorizationBudget{{pqScheme: nativefalcon.Scheme, mutable: true}}, resourcePlan, 0, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		if info.TotalFees != 2_000 || uint64(txns[0].Fee) != 3_000 || len(info.FeeIndices) != 1 || info.FeeIndices[0] != 0 {
			t.Fatalf("fee result = %#v fee %d, want delta 2000/final 3000/index [0]", info, txns[0].Fee)
		}
	})

	t.Run("honors group pooling", func(t *testing.T) {
		txns := []types.Transaction{baseTxn, baseTxn}
		txns[0].Fee = 4_000
		info, err := applyGroupFees(txns, []authorizationBudget{{mutable: true}, {pqScheme: nativefalcon.Scheme, mutable: true}}, lsigresource.Plan{TransactionCount: 2, GroupSize: 2}, 0, nil, false)
		if err != nil || info.TotalFees != 0 {
			t.Fatalf("applyGroupFees() = info %#v, error %v; want pooled fee accepted", info, err)
		}
	})

	t.Run("preserves client-paid oversized note surcharge", func(t *testing.T) {
		txn := baseTxn
		txn.Note = make([]byte, 1_025)
		txn.Fee = 1_001
		txns := []types.Transaction{txn}
		info, err := applyGroupFees(txns, []authorizationBudget{{pqScheme: nativefalcon.Scheme, mutable: true}}, resourcePlan, 0, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		if info.TotalFees != 2_000 || uint64(txns[0].Fee) != 3_001 {
			t.Fatalf("oversized-note fee = info %#v fee %d, want delta 2000/final 3001", info, txns[0].Fee)
		}
	})

	t.Run("rejects an ordinary client fee deficit", func(t *testing.T) {
		txn := baseTxn
		txn.Note = make([]byte, 1_025)
		txns := []types.Transaction{txn}
		_, err := applyGroupFees(txns, []authorizationBudget{{pqScheme: nativefalcon.Scheme, mutable: true}}, resourcePlan, 0, nil, false)
		if err == nil || !strings.Contains(err.Message, "client-supplied group") {
			t.Fatalf("error = %#v, want ordinary fee rejection", err)
		}
	})

	t.Run("rejects immutable underfunding", func(t *testing.T) {
		txns := []types.Transaction{baseTxn}
		_, err := applyGroupFees(txns, []authorizationBudget{{pqScheme: nativefalcon.Scheme}}, resourcePlan, 0, nil, true)
		if err == nil || !strings.Contains(err.Message, "immutable group") {
			t.Fatalf("error = %#v, want immutable fee rejection", err)
		}
	})
}

func TestApplyGroupFeesCombinesDummyProgramAndPQUsage(t *testing.T) {
	txns := []types.Transaction{
		{Type: types.PaymentTx, Header: types.Header{Fee: 1_000}},
		{Type: types.PaymentTx},
	}
	resourcePlan := lsigresource.Plan{
		TransactionCount:      1,
		DummyCount:            1,
		GroupSize:             2,
		ChargedProgramBytes:   2_500,
		ProgramFeeFactorUsage: 250_000,
	}
	info, err := applyGroupFees(
		txns,
		[]authorizationBudget{{pqScheme: nativefalcon.Scheme, mutable: true}},
		resourcePlan,
		1,
		[]int{0},
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	// Two transaction bases (2000), native Falcon (2000), and the priced
	// program (250) require 4250 total. The original paid 1000.
	if info.TotalFees != 3_250 || uint64(txns[0].Fee) != 4_250 {
		t.Fatalf("fee result = %#v, fee %d; want delta 3250/final 4250", info, txns[0].Fee)
	}
	if info.DummyFeeContribution != 1_000 || info.ProgramFeeContribution != 250 || info.NativePQFeeContribution != 2_000 {
		t.Fatalf("fee contributions = %#v", info)
	}
	if len(info.FeeIndices) != 1 || info.FeeIndices[0] != 0 {
		t.Fatalf("fee indices = %v, want [0]", info.FeeIndices)
	}
}

func TestApplyGroupFeesUsesExistingPooledFees(t *testing.T) {
	txns := []types.Transaction{
		{Type: types.PaymentTx, Header: types.Header{Fee: 5_000}},
		{Type: types.PaymentTx},
	}
	info, err := applyGroupFees(
		txns,
		[]authorizationBudget{{mutable: true}},
		lsigresource.Plan{TransactionCount: 1, DummyCount: 1, GroupSize: 2},
		1,
		[]int{0},
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if info.TotalFees != 0 || len(info.FeeIndices) != 0 || uint64(txns[0].Fee) != 5_000 {
		t.Fatalf("pooled overpayment was mutated: info=%#v fee=%d", info, txns[0].Fee)
	}
}

func TestApplyGroupFeesChargesTopLevelNativePQBeforeLogicSig(t *testing.T) {
	txns := []types.Transaction{
		{Type: types.PaymentTx, Header: types.Header{Fee: 1_000}},
		{Type: types.PaymentTx, Header: types.Header{Fee: 1_000}},
	}
	info, err := applyGroupFees(
		txns,
		[]authorizationBudget{{mutable: true}, {pqScheme: nativefalcon.Scheme, mutable: true}},
		lsigresource.Plan{TransactionCount: 2, GroupSize: 2},
		0,
		[]int{0},
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if info.TotalFees != 2_000 {
		t.Fatalf("fee delta = %d, want 2000", info.TotalFees)
	}
	if got := uint64(txns[0].Fee); got != 1_000 {
		t.Fatalf("LogicSig fee = %d, want preserved fee 1000", got)
	}
	if got := uint64(txns[1].Fee); got != 3_000 {
		t.Fatalf("native-PQ sponsor fee = %d, want 3000", got)
	}
	if len(info.FeeIndices) != 1 || info.FeeIndices[0] != 1 {
		t.Fatalf("fee indices = %v, want [1]", info.FeeIndices)
	}
}

func TestApplyGroupFeesHonorsZeroBoundedFeeCeiling(t *testing.T) {
	txns := []types.Transaction{
		{Type: types.PaymentTx},
		{Type: types.PaymentTx, Header: types.Header{Fee: 2_000}},
	}
	info, err := applyGroupFees(
		txns,
		[]authorizationBudget{
			{mutable: true, maxFeeConstrained: true, maxFee: 0},
			{mutable: true},
		},
		lsigresource.Plan{
			TransactionCount:      2,
			GroupSize:             2,
			ProgramFeeFactorUsage: 1_000_000,
		},
		0,
		[]int{0},
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if txns[0].Fee != 0 || txns[1].Fee != 3_000 {
		t.Fatalf("fees = [%d %d], want [0 3000]", txns[0].Fee, txns[1].Fee)
	}
	if info.TotalFees != 1_000 || len(info.FeeIndices) != 1 || info.FeeIndices[0] != 1 {
		t.Fatalf("fee info = %#v, want 1000 assigned to slot 1", info)
	}
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
			PlannerIdentitySnapshot{}, nil, map[int]bool{0: true}, map[int]bool{}, map[int][]byte{0: raw},
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
		base64.StdEncoding.EncodeToString(genesisHash[:]): "customnet_test",
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
		keyTypes: map[string]string{authorizer: nativefalcon.KeyType},
	}, PlannerOptions{GenesisHashResolver: resolver})
	plan, planErr := planner.PlanGroup(signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{
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
	if !strings.Contains(description, "Required native Falcon contribution: 2000 microAlgos") || !strings.Contains(description, "Group fee adjustment: +2000 microAlgos") {
		t.Fatalf("approval description did not disclose native PQ fee mutation:\n%s", description)
	}
}
