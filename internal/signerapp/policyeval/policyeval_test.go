// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyeval

import (
	"errors"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
)

// The signing paths' verdicts are frozen by the fixtures in
// test/contracts/policy/v1/verdicts, run through the daemon by
// internal/signerapp/signing. These tests pin the evaluator's own contract.

func signerPolicy(t *testing.T, sparse string) *policy.Config {
	t.Helper()
	return policytest.Compile(t, noderole.RoleSigner, policy.DefaultKey, sparse)
}

func pay(sender, receiver byte, amount uint64) types.Transaction {
	return types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: types.Address{sender}, Fee: 1000},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: types.Address{receiver}, Amount: types.MicroAlgos(amount)},
	}
}

func TestEvaluateKeepsGroupIndicesOfSparseSlots(t *testing.T) {
	strict := signerPolicy(t, "")
	group := []types.Transaction{pay(1, 2, 1), pay(3, 4, 1), pay(5, 6, 1)}
	verdict, err := Evaluate(Input{Group: group, Slots: []Slot{{Index: 0, Policy: strict}, {Index: 2, Policy: strict}}})
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Outcome != Reject || len(verdict.Violations) != 2 {
		t.Fatalf("verdict = %+v, want two violations", verdict)
	}
	if verdict.Violations[0].TxnIndex != 0 || verdict.Violations[1].TxnIndex != 2 {
		t.Fatalf("violation indices = %d, %d; want 0, 2", verdict.Violations[0].TxnIndex, verdict.Violations[1].TxnIndex)
	}
}

func TestEvaluateMissingPolicyIsAnErrorNotARejection(t *testing.T) {
	group := []types.Transaction{pay(1, 2, 1), pay(3, 4, 1)}
	verdict, err := Evaluate(Input{Group: group, Slots: []Slot{{Index: 0, Policy: signerPolicy(t, "")}, {Index: 1}}})
	if !errors.Is(err, ErrPolicyNotLoaded) {
		t.Fatalf("err = %v, want ErrPolicyNotLoaded", err)
	}
	if verdict.Outcome != Default || verdict.Violations != nil {
		t.Fatalf("verdict = %+v, want none alongside the error", verdict)
	}
}

func TestEvaluateTiers(t *testing.T) {
	open := `"transfer_policy": {"on_no_route": "operator_default"}`
	selfPay := pay(1, 1, 0)
	single := &PlanFacts{RequestCount: 1, AuthAddressPresent: true}
	tests := []struct {
		name    string
		sparse  string
		txn     types.Transaction
		class   SlotClass
		plan    *PlanFacts
		forced  string
		outcome Outcome
		ruleID  string
	}{
		{name: "nothing decides", sparse: `{` + open + `}`, txn: pay(1, 2, 5), outcome: Default},
		{name: "type review", sparse: `{"transaction_types": {"*": "allow", "pay": "review"}, ` + open + `}`, txn: pay(1, 2, 5), outcome: Review, ruleID: policy.TransactionTypeRuleID("pay")},
		{name: "forced review with no rule", sparse: `{` + open + `}`, txn: pay(1, 2, 5), forced: "forced", outcome: Review, ruleID: "forced"},
		{name: "forced review replaces the rule", sparse: `{"transaction_types": {"*": "allow", "pay": "review"}, ` + open + `}`, txn: pay(1, 2, 5), forced: "forced", outcome: Review, ruleID: "forced"},
		{name: "self no-op approves", sparse: `{"auto_approve_self_noop_transfer": true, ` + open + `}`, txn: selfPay, plan: single, outcome: Approve, ruleID: policy.AutoApproveSelfNoOpTransferRuleID},
		{name: "no plan, no approval", sparse: `{"auto_approve_self_noop_transfer": true, ` + open + `}`, txn: selfPay, outcome: Default},
		{name: "review outranks approval", sparse: `{"auto_approve_self_noop_transfer": true, "transaction_types": {"*": "allow", "pay": "review"}, ` + open + `}`, txn: selfPay, plan: single, outcome: Review, ruleID: policy.TransactionTypeRuleID("pay")},
		{name: "a foreign slot is not denied", sparse: `{}`, txn: pay(1, 2, 5), class: SlotForeign, outcome: Default},
		{name: "a foreign slot's warning asks for review", sparse: `{}`, txn: func() types.Transaction { tx := pay(1, 1, 0); tx.RekeyTo = types.Address{9}; return tx }(), class: SlotForeign, outcome: Review, ruleID: policy.AlwaysReviewWarningsRuleID},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			slot := Slot{Index: 0, Class: tc.class}
			if tc.class == SlotSigner {
				slot.Policy = signerPolicy(t, tc.sparse)
			}
			verdict, err := Evaluate(Input{Group: []types.Transaction{tc.txn}, Slots: []Slot{slot}, Plan: tc.plan, ForcedReviewRuleID: tc.forced})
			if err != nil {
				t.Fatal(err)
			}
			if verdict.Outcome != tc.outcome || verdict.RuleID != tc.ruleID {
				t.Fatalf("verdict = %+v, want outcome %d rule %q", verdict, tc.outcome, tc.ruleID)
			}
		})
	}
}

func TestEvaluateIsPure(t *testing.T) {
	cfg := signerPolicy(t, "")
	group := []types.Transaction{pay(1, 2, 1)}
	in := Input{Group: group, Slots: []Slot{{Index: 0, Policy: cfg}}}
	first, err := Evaluate(in)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Evaluate(in)
	if err != nil {
		t.Fatal(err)
	}
	if policy.JoinLintViolations(first.Violations) != policy.JoinLintViolations(second.Violations) {
		t.Fatalf("repeated evaluations differ: %+v vs %+v", first, second)
	}
	if group[0].Amount != 1 || group[0].Group != (types.Digest{}) {
		t.Fatalf("Evaluate changed its input: %+v", group[0])
	}
}
