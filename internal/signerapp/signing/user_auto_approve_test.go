// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// Exercise the real policy gate and each approval adapter without an admin
// connection. Auto-approve must satisfy every review source, while policy
// rejections must still stop the request before any approval adapter runs.
func TestUserAutoApproveReviewAndRejectAcrossSigningPaths(t *testing.T) {
	payment := types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: types.Address{1}},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: types.Address{2}, Amount: 11},
	}
	tests := []struct {
		name       string
		policyJSON string
		mutate     func(*types.Transaction)
		foreign    bool
		forcedRule string
		reject     bool
	}{
		{name: "fallback", policyJSON: `{}`},
		{name: "warning", policyJSON: `{"always_review_warnings":true}`, mutate: func(tx *types.Transaction) { tx.Fee = 1_000_001 }},
		{name: "rotation_rekey_warning", policyJSON: `{"always_review_warnings":true}`, mutate: func(tx *types.Transaction) { tx.RekeyTo = types.Address{3} }},
		{name: "transaction_type", policyJSON: `{"transaction_types":{"*":"allow","pay":"review"}}`},
		{name: "route_miss", policyJSON: `{"transfer_policy":{"on_no_route":"review","routes":[]}}`},
		{name: "foreign_warning", policyJSON: `{"always_review_warnings":false}`, foreign: true},
		{name: "bounded_admin", policyJSON: `{}`, forcedRule: policy.BoundedAdminOperationRequiresReviewRuleID},
		{name: "rejected_type", policyJSON: `{"transaction_types":{"*":"reject"}}`, reject: true},
		{name: "rejected_fee", policyJSON: `{"max_fee_microalgos":"1000","always_review_warnings":true}`, mutate: func(tx *types.Transaction) { tx.Fee = 1_000_001 }, reject: true},
		{name: "rejected_route", policyJSON: `{"transfer_policy":{"on_no_route":"reject","routes":[]}}`, reject: true},
	}
	for _, tc := range tests {
		for _, path := range []string{"single", "group", "component"} {
			for _, auto := range []bool{false, true} {
				mode := "manual"
				if auto {
					mode = "auto"
				}
				t.Run(tc.name+"/"+path+"/"+mode, func(t *testing.T) {
					cfg := routingPolicyConfigForSigningTest(t, tc.policyJSON)
					if !strings.Contains(tc.policyJSON, "transfer_policy") {
						cfg.TransferPolicy.OnNoRoute = policy.TransferOnNoRouteOperatorDefault
					}
					txn := payment
					// Give route evaluation a known network.
					txn.GenesisHash = testnetPaymentTransaction(t, txn.Sender.String(), txn.Receiver.String(), 11).GenesisHash
					if tc.mutate != nil {
						tc.mutate(&txn)
					}
					txns := []types.Transaction{txn}
					foreign := map[int]bool{}
					if path != "single" || tc.foreign {
						txns = append(txns, payment)
						txns[1].GenesisHash = txn.GenesisHash
					}
					if tc.foreign {
						foreign[1] = true
						txns[1].RekeyTo = types.Address{4}
					}
					approval := &ApprovalService{UserAutoApprove: &auto, HasClient: func() bool { return false }}
					svc := &Service{Approval: approval, PolicyFor: fixedPolicy(cfg)}
					approvalCalls := 0
					rule, err := svc.runApprovalGates(context.Background(), gateInput{
						AllTxns: txns, EvalCount: len(txns), ForeignIndices: foreign,
						KnownAddresses:     map[string]bool{types.Address{3}.String(): true},
						ForcedReviewRuleID: tc.forcedRule,
						RequestOperatorApproval: func(ctx context.Context, rule string) *ServiceError {
							approvalCalls++
							switch path {
							case "single":
								return approval.requestSingleTxnApprovalWithContext(ctx, "", signerapi.SignRequest{}, txns, txns, 0, 0, 0, rule)
							case "group":
								return approval.requestGroupApprovalWithContext(ctx, signerapi.GroupSignRequest{}, &PlanResult{}, "", 0, 0, txns, rule)
							default:
								return approval.requestComponentApprovalWithContext(ctx, &ComponentSignPlan{}, txns, "", 0, 0, rule)
							}
						},
					}, nil)
					if tc.reject {
						if err == nil || err.Kind != ErrorForbidden || approvalCalls != 0 {
							t.Fatalf("error = %v, approval calls = %d; want hard rejection before approval", err, approvalCalls)
						}
						return
					}
					if tc.name != "fallback" && rule == "" {
						t.Fatal("expected a review rule to match and remain available for audit")
					}
					if approvalCalls != 1 {
						t.Fatalf("approval calls = %d, want 1", approvalCalls)
					}
					if auto && err != nil {
						t.Fatalf("auto-approve requires no admin client: %v", err)
					}
					if !auto && (err == nil || err.Kind != ErrorUnavailable) {
						t.Fatalf("manual review without admin: error = %v, want unavailable", err)
					}
				})
			}
		}
	}
}
