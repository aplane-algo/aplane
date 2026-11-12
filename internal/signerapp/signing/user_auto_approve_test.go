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
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/txnutil"
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
		{name: "bounded_rekey", policyJSON: `{}`, forcedRule: policy.BoundedRekeyRequiresReviewRuleID},
		{name: "rejected_type", policyJSON: `{"transaction_types":{"*":"reject"}}`, reject: true},
		{name: "rejected_fee", policyJSON: `{"max_fee_microalgos":"1000","always_review_warnings":true}`, mutate: func(tx *types.Transaction) { tx.Fee = 1_000_001 }, reject: true},
		{name: "rejected_route", policyJSON: `{"transfer_policy":{"on_no_route":"reject","routes":[]}}`, reject: true},
	}
	for _, tc := range tests {
		for _, path := range []string{"single", "group"} {
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
								return approval.requestSingleTxnApprovalWithContext(ctx, "", signerapi.SignRequest{}, txns, txns, "", 0, 0, rule, nil)
							default:
								return approval.requestGroupApprovalWithContext(ctx, signerapi.GroupSignRequest{}, &PlanResult{}, "", 0, 0, txns, rule)
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

// A generic LogicSig has no key: its program alone authorizes, so a rekey to
// one this signer holds is foreign. Under the shipped default it is rejected
// before approval, User Auto-Approve included. With allow_rekeys it goes on to
// review, and the warning says control is lost.
func TestRekeyToHeldGenericLogicSigIsForeign(t *testing.T) {
	key := types.Address{1}
	generic := types.Address{7}
	deps := stubPlannerDeps{
		keyTypes: map[string]string{key.String(): "ed25519", generic.String(): "aplane.htlc.v1"},
		keyMetadata: map[string]PlannerKeyMetadata{
			key.String():     {Category: "ed25519"},
			generic.String(): {Category: lsigprovider.CategoryGenericLsig},
		},
	}
	planner := NewPlanner(deps, PlannerOptions{GenesisHashResolver: apconfig.DefaultGenesisHashNetworkResolver()})
	txn := testnetPaymentTransaction(t, key.String(), key.String(), 0)
	txn.Fee = 1_000
	txn.RekeyTo = generic
	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: key.String(), TxnBytesHex: txnutil.EncodeWithPrefixHex(txn)}}}
	plan, planErr := planner.PlanGroup(req)
	if planErr != nil {
		t.Fatalf("PlanGroup() error = %v", planErr)
	}

	shipped := func(rekeys policy.SignerRekeys) *policy.Config {
		doc := policytest.EmbeddedDefault(t, noderole.RoleSigner)
		doc = strings.Replace(doc, `"rekeys": "reject_foreign_rekey"`, `"rekeys": "`+string(rekeys)+`"`, 1)
		decoded, err := policy.DecodePolicyV1([]byte(doc), policy.DefaultKey, noderole.RoleSigner)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := decoded.Compile(policy.DefaultConfig())
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Rekeys != rekeys || !cfg.AlwaysReviewWarnings {
			t.Fatalf("compiled rekeys = %q, always_review_warnings = %v; want %q and true", cfg.Rekeys, cfg.AlwaysReviewWarnings, rekeys)
		}
		return cfg
	}

	for _, tc := range []struct {
		name   string
		cfg    *policy.Config
		reject bool
	}{
		{name: "shipped_default", cfg: shipped(policy.RekeysRejectForeign), reject: true},
		{name: "allow_rekeys", cfg: shipped(policy.RekeysAllow)},
	} {
		for _, auto := range []bool{false, true} {
			mode := "manual"
			if auto {
				mode = "auto"
			}
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				var warnings []signerapproval.Violation
				prompted, approvalCalls := false, 0
				approval := &ApprovalService{
					UserAutoApprove:               &auto,
					GenerateTxnDescriptionFromTxn: func(types.Transaction) string { return "txn" },
					// The runtime's set, which leaves out generic LogicSigs the
					// same way (TestKnownAddressesLeaveOutGenericLogicSigs).
					KnownAddresses: func() map[string]bool { return rekeyHeldAddressesFromSnapshot(deps.Snapshot()) },
					HasClient:      func() bool { return true },
					RequestSigningApprovalContext: func(_ context.Context, _, _, _, _ string, _, _ uint64, v []signerapproval.Violation, _ time.Duration) (bool, error) {
						prompted = true
						warnings = v
						return true, nil
					},
				}
				svc := &Service{Approval: approval, PolicyFor: fixedPolicy(tc.cfg), Planner: planner}
				rule, err := svc.runApprovalGates(context.Background(), gateInput{
					AllTxns: plan.AllTxns, EvalCount: len(req.Requests),
					PassthroughIndices: plan.PassthroughIndices, ForeignIndices: plan.ForeignIndices,
					AuthKeys:       []string{key.String()},
					KnownAddresses: svc.knownAddresses(plan),
					RequestOperatorApproval: func(ctx context.Context, rule string) *ServiceError {
						approvalCalls++
						return approval.requestSingleTxnApprovalWithContext(ctx, "", req.Requests[0], plan.AllTxns, plan.AllTxns[:1], "", 0, 0, rule, nil)
					},
				}, nil)
				if tc.reject {
					if err == nil || err.Kind != ErrorForbidden || !strings.Contains(err.Message, policy.RejectForeignRekeyRuleID) || approvalCalls != 0 {
						t.Fatalf("error = %v, approval calls = %d; want %s before approval", err, approvalCalls, policy.RejectForeignRekeyRuleID)
					}
					return
				}
				if err != nil || rule != policy.AlwaysReviewWarningsRuleID || approvalCalls != 1 {
					t.Fatalf("rule = %q, error = %v, approval calls = %d; want review by %s", rule, err, approvalCalls, policy.AlwaysReviewWarningsRuleID)
				}
				if auto {
					if prompted {
						t.Fatal("User Auto-Approve prompted the operator")
					}
					return
				}
				if !prompted || len(warnings) != 1 {
					t.Fatalf("prompted = %v, warnings = %+v; want one rekey warning", prompted, warnings)
				}
				if msg := warnings[0].Message; !strings.Contains(msg, "YOU WILL LOSE CONTROL OF THIS ACCOUNT") || strings.Contains(msg, "You possess the keys") {
					t.Fatalf("rekey warning = %q, want the lose-control text", msg)
				}
			})
		}
	}
}
