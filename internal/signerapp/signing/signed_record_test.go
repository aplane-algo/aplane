// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// The signed record names the transactions as signed: planning added a dummy,
// raised the fee and set the group ID, so the request's transaction ID is not
// what was signed.
func TestSignedRecordDescribesTheTransactionsAsSigned(t *testing.T) {
	planner, authorizer, requested := lsigDummyPlanner(t, nil)
	req := signerapi.GroupSignRequest{RequestID: "req-1", Requests: []signerapi.SignRequest{{
		AuthAddress: authorizer, TxnBytesHex: txnutil.EncodeWithPrefixHex(requested),
	}}}
	plan, planErr := planner.PlanGroup(req)
	if planErr != nil {
		t.Fatal(planErr)
	}
	if plan.DummiesNeeded == 0 || plan.AllTxns[0].Fee <= requested.Fee || plan.AllTxns[0].Group == (types.Digest{}) {
		t.Fatalf("plan = %d dummies, fee %d, group %x; want a dummy, a raised fee and a group", plan.DummiesNeeded, plan.AllTxns[0].Fee, plan.AllTxns[0].Group)
	}

	audit := &testAuditLogger{}
	(&Service{AuditLog: audit}).logSuccessfulSignatures(req, plan, signedGroupOf(plan.AllTxns, len(plan.DummyTxns)), "")
	if len(audit.approved) != 1 {
		t.Fatalf("approvals = %d, want one for the account; dummies are recorded in its group", len(audit.approved))
	}
	got := audit.approved[0].record
	signed := plan.AllTxns[0]
	if got.TxID != algocrypto.GetTxID(signed) || got.TxID == algocrypto.GetTxID(requested) {
		t.Fatalf("recorded txid %s, want the signed %s, not the requested %s", got.TxID, algocrypto.GetTxID(signed), algocrypto.GetTxID(requested))
	}
	if got.Fee != uint64(signed.Fee) {
		t.Fatalf("recorded fee %d, want the signed fee %d", got.Fee, signed.Fee)
	}
	if want := base64.StdEncoding.EncodeToString(signed.Group[:]); got.GroupID != want {
		t.Fatalf("recorded group %q, want %q", got.GroupID, want)
	}
	if len(got.GroupTxIDs) != len(plan.AllTxns) || got.DummyCount != plan.DummiesNeeded {
		t.Fatalf("recorded group %v with %d dummies, want %d transactions and %d dummies", got.GroupTxIDs, got.DummyCount, len(plan.AllTxns), plan.DummiesNeeded)
	}
	for i, txn := range plan.AllTxns {
		if got.GroupTxIDs[i] != algocrypto.GetTxID(txn) {
			t.Fatalf("group txid %d = %s, want %s", i, got.GroupTxIDs[i], algocrypto.GetTxID(txn))
		}
	}
	if got.AuthAddress != authorizer || got.TxnSender != signed.Sender.String() || got.Details != "txn 1/1 signed" {
		t.Fatalf("record = %+v", got)
	}
}

// A transaction signed alone records no group.
func TestSignedRecordOfAnUngroupedTransaction(t *testing.T) {
	txn := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{1}, Fee: 1_000}}
	got := signedGroupOf([]types.Transaction{txn}, 0).record(0, "A", "txn 1/1 signed", "rule")
	if got.TxID != algocrypto.GetTxID(txn) || got.Fee != 1_000 || got.PolicyRuleID != "rule" {
		t.Fatalf("record = %+v", got)
	}
	if got.GroupID != "" || got.GroupTxIDs != nil || got.DummyCount != 0 {
		t.Fatalf("an ungrouped transaction recorded a group: %+v", got)
	}
}

// A refused request records the refusal and nothing as signed.
func TestRefusedSignRecordsNothingAsSigned(t *testing.T) {
	audit := &testAuditLogger{}
	service := &Service{
		Planner:                       &Planner{},
		Approval:                      &ApprovalService{},
		Executor:                      &Executor{},
		AuditLog:                      audit,
		IsUnlocked:                    func() bool { return true },
		GenerateTxnDescriptionFromTxn: func(types.Transaction) string { return "txn" },
		PolicyFor: fixedPolicy(&policy.Config{TransactionTypes: policytest.AllowAllTypes(),
			Rekeys: policy.RekeysRejectForeign,
		}),
	}
	txn := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{2}, RekeyTo: types.Address{1}}}
	req := signerapi.GroupSignRequest{RequestID: "refused-1", Requests: []signerapi.SignRequest{{AuthAddress: "AUTHADDR"}}}
	plan := &PlanResult{
		AllTxns:               []types.Transaction{txn},
		PassthroughIndices:    map[int]bool{},
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        map[int]bool{},
	}

	if result, err := service.signGroupWithPlanContext(context.Background(), req, nil, plan); result != nil || err == nil {
		t.Fatalf("result %v, error %v; want a refusal", result, err)
	}
	if len(audit.rejected) != 1 || !strings.HasPrefix(audit.rejected[0].reason, auditPolicyRejected) {
		t.Fatalf("rejections = %+v, want one policy rejection", audit.rejected)
	}
	if len(audit.approved) != 0 {
		t.Fatalf("a refused request was recorded as signed: %+v", audit.approved)
	}
}
