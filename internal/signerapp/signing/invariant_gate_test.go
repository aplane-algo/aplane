// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func keyregTxn(sender types.Address, online, nonparticipation bool) types.Transaction {
	txn := types.Transaction{Type: types.KeyRegistrationTx, Header: types.Header{Sender: sender, Fee: 1000}}
	if online {
		txn.VotePK = types.VotePK{1}
		txn.SelectionPK = types.VRFPK{2}
		txn.VoteFirst, txn.VoteLast, txn.VoteKeyDilution = 1, 1000, 100
	}
	txn.Nonparticipation = nonparticipation
	return txn
}

func requireNonparticipationRefusal(t *testing.T, err *ServiceError, slot string) {
	t.Helper()
	if err == nil {
		t.Fatal("nonparticipating keyreg was not refused")
	}
	if err.HTTPStatus() != 403 || !strings.HasPrefix(err.Message, slot) || !strings.Contains(err.Message, nonparticipationRefusal) {
		t.Fatalf("error = %q (%d), want a 403 nonparticipation refusal for %q", err.Message, err.HTTPStatus(), slot)
	}
}

func TestRejectNonparticipation(t *testing.T) {
	sender := types.Address{1}
	pay := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: sender}}
	group := []types.Transaction{pay, keyregTxn(sender, false, true)}

	requireNonparticipationRefusal(t, rejectNonparticipation(group, []int{0, 1}), "transaction 2:")
	// Positions this signer doesn't sign are not judged.
	if err := rejectNonparticipation(group, []int{0}); err != nil {
		t.Fatalf("an unsigned position was judged: %v", err)
	}
	for name, txn := range map[string]types.Transaction{
		"offline keyreg": keyregTxn(sender, false, false),
		"online keyreg":  keyregTxn(sender, true, false),
	} {
		if err := rejectNonparticipation([]types.Transaction{txn}, []int{0}); err != nil {
			t.Fatalf("%s refused: %v", name, err)
		}
	}
	// The invariants judge exactly the positions policy judges as this
	// signer's: not passthrough, foreign or dummy ones.
	four := make([]types.Transaction, 4)
	slots := clientSlots(four, 3, map[int]bool{1: true}, map[int]bool{2: true}, nil, nil, nil)
	if got := signerPositions(slots); len(got) != 1 || got[0] != 0 {
		t.Fatalf("signerPositions = %v, want [0]", got)
	}
	if got := signerPositions(clientSlots(four[:2], 2, nil, nil, nil, nil, nil)); len(got) != 2 {
		t.Fatalf("signerPositions = %v, want both positions", got)
	}
}

// signKeyregForTest runs txn through /sign's planned path with a policy that
// allows every type and auto-approves, so only a signer invariant can stop it
// before execution.
func signKeyregForTest(t *testing.T, plan *PlanResult, req signerapi.GroupSignRequest) (*ServiceError, bool) {
	t.Helper()
	approvalCalled := false
	audit := &testAuditLogger{}
	service := &Service{
		AuditLog: audit,
		Approval: &ApprovalService{
			UserAutoApprove:               userAutoApproveDefault(true),
			GenerateTxnDescriptionFromTxn: func(types.Transaction) string { return "txn" },
			HasClient:                     func() bool { return true },
			RequestSigningApproval: func(string, string, string, string, uint64, uint64, []signerapproval.Violation, time.Duration) (bool, error) {
				approvalCalled = true
				return true, nil
			},
		},
		Executor:                      &Executor{},
		GenerateTxnDescriptionFromTxn: func(types.Transaction) string { return "txn" },
		IsUnlocked:                    func() bool { return true },
		BeforeExecute: func() (func(), *ServiceError) {
			return nil, forbidden("reached execution")
		},
		PolicyFor: fixedPolicy(&policy.Config{TransactionTypes: policytest.AllowAllTypes()}),
	}
	_, err := service.signGroupWithPlanContext(context.Background(), req, nil, plan)
	if err != nil && strings.Contains(err.Message, nonparticipationRefusal) {
		if len(audit.rejected) == 0 || audit.rejected[0].reason != auditSignerInvariant+err.Message {
			t.Fatalf("audit = %#v, want the refusal audited as %q", audit.rejected, auditSignerInvariant)
		}
	}
	return err, approvalCalled
}

// Refused on /sign even though the policy allows keyreg and auto-approves:
// the invariant comes before the verdict.
func TestSignRefusesNonparticipationThatPolicyAllows(t *testing.T) {
	sender := types.Address{1}
	plan := func(txns ...types.Transaction) *PlanResult {
		return &PlanResult{AllTxns: txns, PassthroughIndices: map[int]bool{}, PassthroughSignedTxns: map[int][]byte{}, ForeignIndices: map[int]bool{}}
	}
	single := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: "AUTHADDR", TxnBytesHex: "5458aa"}}}

	err, approvalCalled := signKeyregForTest(t, plan(keyregTxn(sender, false, true)), single)
	requireNonparticipationRefusal(t, err, "transaction 1:")
	if approvalCalled {
		t.Fatal("the operator was asked about a refused keyreg")
	}

	for name, txn := range map[string]types.Transaction{
		"offline keyreg": keyregTxn(sender, false, false),
		"online keyreg":  keyregTxn(sender, true, false),
	} {
		err, _ := signKeyregForTest(t, plan(txn), single)
		if err == nil || !strings.Contains(err.Message, "reached execution") {
			t.Fatalf("%s: error = %v, want it to reach execution", name, err)
		}
	}

	// A foreign position isn't this signer's signature.
	foreignPlan := plan(types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: sender}}, keyregTxn(types.Address{2}, false, true))
	foreignPlan.ForeignIndices = map[int]bool{1: true}
	foreignPlan.HasForeign = true
	withForeign := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{
		{AuthAddress: "AUTHADDR", TxnBytesHex: "5458aa"},
		{TxnBytesHex: "5458bb"},
	}}
	if err, _ := signKeyregForTest(t, foreignPlan, withForeign); err == nil || !strings.Contains(err.Message, "reached execution") {
		t.Fatalf("foreign nonparticipating keyreg: error = %v, want it to reach execution", err)
	}
}

// On a cosigner the invariant runs before the cosigner's policy, so a policy
// that allows keyreg (once cosigners may allow any type) can't let it through.
// It is audited as a signer invariant, not as a policy rejection.
func TestCosignerRefusesNonparticipationBeforePolicy(t *testing.T) {
	componentKey := testFalconComponentSelector(t, 0xab)
	txn := keyregTxn(types.Address{40}, false, true)
	txn.FirstValid, txn.LastValid = 10, 20
	txn.GenesisHash = testDigest(t, apconfig.AlgorandTestnetGenesisHash)
	store := &componentKeyStore{}
	audit := &limitedCosignerAuditLogger{}
	service := cosignerTestServiceFor(componentKey, wildcardCosignerPolicy(t))
	service.AuditLog = audit

	_, err := service.signComponentWithContext(context.Background(), componentPlanRequest{
		RequestID:     "cmp-cosigner-nonparticipation",
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  componentKey,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, newComponentKeySession(store))
	requireNonparticipationRefusal(t, err, "transaction 1:")
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want 0: the key loaded for a refused request", store.calls)
	}
	if len(audit.limited) != 1 || audit.limited[0].reason != auditSignerInvariant+"transaction 1: "+nonparticipationRefusal {
		t.Fatalf("audit = %#v, want one signer_invariant rejection", audit.limited)
	}
}

// A request for a component key this cosigner doesn't hold is refused as such,
// before the invariants run: no signer_invariant entry is written for a key
// the caller made up.
func TestCosignerChecksTheKeyBeforeTheInvariant(t *testing.T) {
	componentKey := testFalconComponentSelector(t, 0xab)
	txn := keyregTxn(types.Address{40}, false, true)
	txn.FirstValid, txn.LastValid = 10, 20
	txn.GenesisHash = testDigest(t, apconfig.AlgorandTestnetGenesisHash)
	audit := &limitedCosignerAuditLogger{}
	service := cosignerTestServiceFor(componentKey, wildcardCosignerPolicy(t))
	service.HoldsCosignerKey = func(string) bool { return false }
	service.AuditLog = audit

	_, err := service.signComponentWithContext(context.Background(), componentPlanRequest{
		RequestID:     "cmp-cosigner-unknown-key",
		Role:          ComponentSignRoleCosigner,
		ComponentKey:  componentKey,
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txn)},
		TargetIndices: []int{0},
	}, newComponentKeySession(&componentKeyStore{}))
	if err == nil || err.HTTPStatus() != 400 || !strings.Contains(err.Message, "not found") {
		t.Fatalf("err = %v, want 400 for a key this node doesn't hold", err)
	}
	if len(audit.limited) != 0 {
		t.Fatalf("audit = %#v, want nothing audited for an unknown key", audit.limited)
	}
}

// A signed position outside the group is a caller bug: the invariants fail
// closed instead of skipping it.
func TestSignerInvariantsFailClosedOnPositionOutsideGroup(t *testing.T) {
	svc := &Service{}
	txns := []types.Transaction{keyregTxn(types.Address{1}, true, false)}
	if err := svc.rejectSignerInvariants(txns, []int{1}); err == nil || err.HTTPStatus() != 500 {
		t.Fatalf("err = %v, want an internal error", err)
	}
	if err := svc.rejectSignerInvariants(txns, []int{0}); err != nil {
		t.Fatalf("online keyreg refused: %v", err)
	}
}
