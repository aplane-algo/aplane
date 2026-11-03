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
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/pkg/signerapi"
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

	t.Run("never spends a client surplus on the PQ charge", func(t *testing.T) {
		// Slot 0 pays 3000 above its own base, enough to cover the PQ charge
		// under a netting rule. The surplus may be paying for inner
		// transactions, so the signer adds its charge on top instead.
		txns := []types.Transaction{baseTxn, baseTxn}
		txns[0].Fee = 4_000
		info, err := applyGroupFees(txns, []authorizationBudget{{mutable: true}, {pqScheme: nativefalcon.Scheme, mutable: true}}, lsigresource.Plan{TransactionCount: 2, GroupSize: 2}, 0, nil, false)
		if err != nil || info.TotalFees != 2_000 || txns[0].Fee != 4_000 || txns[1].Fee != 3_000 {
			t.Fatalf("applyGroupFees() = info %#v, fees [%d %d], error %v; want the 2000 charge on the PQ slot and the surplus kept", info, txns[0].Fee, txns[1].Fee, err)
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

	t.Run("checks an immutable group without raising it", func(t *testing.T) {
		// A planned group sent back pre-grouped already carries the charge;
		// it is checked against the full requirement and left unchanged.
		txn := baseTxn
		txn.Fee = 3_000
		txns := []types.Transaction{txn}
		info, err := applyGroupFees(txns, []authorizationBudget{{pqScheme: nativefalcon.Scheme}}, resourcePlan, 0, nil, true)
		if err != nil || info.TotalFees != 0 || len(info.FeeIndices) != 0 || txns[0].Fee != 3_000 {
			t.Fatalf("applyGroupFees() = info %#v, fee %d, error %v; want the paid group accepted unchanged", info, txns[0].Fee, err)
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

func TestApplyGroupFeesKeepsClientSurplusForDummies(t *testing.T) {
	// The client pays 4000 above its own base. The dummy's base fee is the
	// signer's charge and is added on top, so the surplus survives intact.
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
	if info.TotalFees != 1_000 || len(info.FeeIndices) != 1 || info.FeeIndices[0] != 0 || uint64(txns[0].Fee) != 6_000 {
		t.Fatalf("dummy charge = info %#v fee %d, want 1000 added on top of the client's 5000", info, txns[0].Fee)
	}
}

// TestApplyGroupFeesChargeDependsOnlyOnShape pins the invariant the rotating
// flow relies on to recover a client's spend from a prepared group: the
// signer's charge is a function of the group's shape, never of its fees.
// However much the client pays, and wherever its surplus sits, the planner
// adds the same amount and the client's own fees are kept.
func TestApplyGroupFeesChargeDependsOnlyOnShape(t *testing.T) {
	shapes := []struct {
		name       string
		txns       []types.Transaction
		budgets    []authorizationBudget
		plan       lsigresource.Plan
		dummies    int
		lsigs      []int
		wantCharge uint64
	}{
		{
			name:       "native PQ",
			txns:       []types.Transaction{{Type: types.PaymentTx}, {Type: types.ApplicationCallTx}},
			budgets:    []authorizationBudget{{pqScheme: nativefalcon.Scheme, mutable: true}, {pqScheme: nativefalcon.Scheme, mutable: true}},
			plan:       lsigresource.Plan{TransactionCount: 2, GroupSize: 2},
			wantCharge: 4_000,
		},
		{
			name:       "LogicSig dummies and priced program",
			txns:       []types.Transaction{{Type: types.PaymentTx}, {Type: types.PaymentTx}, {Type: types.PaymentTx}},
			budgets:    []authorizationBudget{{mutable: true}},
			plan:       lsigresource.Plan{TransactionCount: 1, DummyCount: 2, GroupSize: 3, ProgramFeeFactorUsage: 250_000},
			dummies:    2,
			lsigs:      []int{0},
			wantCharge: 2_250,
		},
		{
			name:       "oversized note beside native PQ",
			txns:       []types.Transaction{{Type: types.PaymentTx, Header: types.Header{Note: make([]byte, 1_025)}}},
			budgets:    []authorizationBudget{{pqScheme: nativefalcon.Scheme, mutable: true}},
			plan:       lsigresource.Plan{TransactionCount: 1, GroupSize: 1},
			wantCharge: 2_000,
		},
	}
	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			// The client's fees on its own slots, from its minimum upward;
			// signer-added dummies always arrive with no fee.
			clientSlots := int(shape.plan.TransactionCount)
			minimum := make([]uint64, clientSlots)
			for i := range minimum {
				minimum[i] = 1_000
			}
			if len(shape.txns[0].Note) > 0 {
				minimum[0] = 1_001
			}
			variants := [][]uint64{minimum}
			for _, surplus := range []uint64{1, 1_999, 34_000} {
				for slot := 0; slot < clientSlots; slot++ {
					fees := append([]uint64(nil), minimum...)
					fees[slot] += surplus
					variants = append(variants, fees)
				}
			}
			for _, fees := range variants {
				txns := append([]types.Transaction(nil), shape.txns...)
				var paid uint64
				for i, fee := range fees {
					txns[i].Fee = types.MicroAlgos(fee)
					paid += fee
				}
				info, err := applyGroupFees(txns, shape.budgets, shape.plan, shape.dummies, shape.lsigs, false)
				if err != nil {
					t.Fatalf("client fees %v: %v", fees, err)
				}
				var total uint64
				for i, txn := range txns {
					total += uint64(txn.Fee)
					if i < clientSlots && uint64(txn.Fee) < fees[i] {
						t.Fatalf("client fees %v: slot %d fee fell to %d", fees, i, txn.Fee)
					}
				}
				if info.TotalFees != shape.wantCharge || total != paid+shape.wantCharge {
					t.Fatalf("client fees %v: charge %d, group total %d; want charge %d on top of %d", fees, info.TotalFees, total, shape.wantCharge, paid)
				}
			}
		})
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
			PlannerRuntimeSnapshot{}, nil, map[int]bool{0: true}, map[int]bool{}, map[int][]byte{0: raw},
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

// planFeeAt plans one transaction from authorizer at the given client fee and
// returns the plan, failing the test on a planning error.
func planFeeAt(t *testing.T, planner *Planner, authorizer string, txn types.Transaction, fee uint64) *PlanResult {
	t.Helper()
	txn.Fee = types.MicroAlgos(fee)
	plan, err := planner.PlanGroup(signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{
		AuthAddress: authorizer, TxnBytesHex: hex.EncodeToString(msgpack.Encode(txn)),
	}}})
	if err != nil {
		t.Fatalf("PlanGroup() at fee %d: %v", fee, err)
	}
	return plan
}

func feeTestResolver(t *testing.T, genesisHash types.Digest) apconfig.GenesisHashNetworkResolver {
	t.Helper()
	resolver, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{
		base64.StdEncoding.EncodeToString(genesisHash[:]): "customnet_test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

// An app call can carry an extra fee that pays for its inner transactions
// out of the group's fee credit. The signer cannot see that, so it must add
// the native Falcon charge on top rather than take it out of the extra fee:
// taking it starved a Mithras deposit of the inner fees its opcode-budget
// loop needed (Nov 2026).
func TestPlanGroupKeepsAnAppCallsInnerFeeSurplusForNativeFalcon(t *testing.T) {
	genesisHash := types.Digest{5}
	authorizer := types.Address{8}.String()
	planner := NewPlanner(stubPlannerDeps{
		keyTypes: map[string]string{authorizer: nativefalcon.KeyType},
	}, PlannerOptions{GenesisHashResolver: feeTestResolver(t, genesisHash)})
	appCall := types.Transaction{
		Type:              types.ApplicationCallTx,
		Header:            types.Header{Sender: types.Address{8}, FirstValid: 1, LastValid: 2, GenesisHash: genesisHash},
		ApplicationFields: types.ApplicationFields{ApplicationCallTxnFields: types.ApplicationCallTxnFields{ApplicationID: 19973}},
	}
	const innerReserve = 34_000
	plan := planFeeAt(t, planner, authorizer, appCall, 1_000+innerReserve)
	if got := uint64(plan.AllTxns[0].Fee); got != 3_000+innerReserve {
		t.Fatalf("planned fee = %d, want the 2000 native Falcon charge on top of 1000 + %d", got, innerReserve)
	}
	if plan.FeeInfo.TotalFees != 2_000 {
		t.Fatalf("fee delta = %d, want 2000", plan.FeeInfo.TotalFees)
	}
}

// The same holds for a LogicSig key: the dummies' base fees and the priced
// program bytes are the signer's charge, the same whatever the client paid.
func TestPlanGroupKeepsAnInnerFeeSurplusForLogicSigDummies(t *testing.T) {
	genesisHash := types.Digest{5}
	authorizer := types.Address{8}.String()
	profile := lsigresource.Profile{
		ProgramBytes: 4_500,
		Default:      &lsigresource.PathProfile{ArgumentBytes: 1_423, MaxOpcodeCost: 39_999},
	}
	planner := NewPlanner(stubPlannerDeps{
		keyTypes: map[string]string{authorizer: "aplane.falcon1024.v1"},
		keyMetadata: map[string]PlannerKeyMetadata{authorizer: {
			Category: "dsa_lsig", PublicKeyHex: "aabb", LogicSigResources: &profile,
		}},
	}, PlannerOptions{GenesisHashResolver: feeTestResolver(t, genesisHash)})
	appCall := types.Transaction{
		Type:              types.ApplicationCallTx,
		Header:            types.Header{Sender: types.Address{8}, FirstValid: 1, LastValid: 2, GenesisHash: genesisHash},
		ApplicationFields: types.ApplicationFields{ApplicationCallTxnFields: types.ApplicationCallTxnFields{ApplicationID: 19973}},
	}
	minimum := planFeeAt(t, planner, authorizer, appCall, 1_000)
	charge := minimum.FeeInfo.TotalFees
	if minimum.DummiesNeeded == 0 || charge < uint64(minimum.DummiesNeeded)*1_000 {
		t.Fatalf("plan at the minimum fee = %d dummies, charge %d; want dummies and their base fees charged", minimum.DummiesNeeded, charge)
	}
	const innerReserve = 34_000
	reserved := planFeeAt(t, planner, authorizer, appCall, 1_000+innerReserve)
	if reserved.FeeInfo.TotalFees != charge || reserved.DummiesNeeded != minimum.DummiesNeeded {
		t.Fatalf("with an inner-fee reserve: charge %d, %d dummies; want the same %d and %d as at the minimum", reserved.FeeInfo.TotalFees, reserved.DummiesNeeded, charge, minimum.DummiesNeeded)
	}
	var total uint64
	for _, txn := range reserved.AllTxns {
		total += uint64(txn.Fee)
	}
	if total != 1_000+innerReserve+charge {
		t.Fatalf("group pays %d, want 1000 + %d reserve + %d charge", total, innerReserve, charge)
	}
}
