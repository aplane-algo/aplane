// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/txnreview"
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

// The rekey rule's truth table, target kind across, rekeys setting down:
//
//	                      foreign   held+valid   held+not-valid
//	reject_all_rekeys     refuse    refuse       refuse (C)
//	reject_foreign_rekey  refuse*   allow        refuse (C)
//	allow_rekeys          allow     allow        refuse (C)
//
// * unless the account's rekey-to list names it. The rekeys setting decides as
// it always has; (C) is the valid_rekey_target signer invariant, which runs
// before policy under every setting and which neither allow_rekeys nor the
// rekey-to list lifts. An account's own address is no column of its own: it
// is a target like any other, held and valid (an ed25519 account), held and
// not valid (a rotating account, or a generic LogicSig whose key records
// false), or foreign. "allow" means the rule refuses nothing and the rekey
// goes on to review, here always_review_warnings, User Auto-Approve on or off.
func TestRekeyRuleTruthTable(t *testing.T) {
	key, valid, htlc, foreign := types.Address{1}, types.Address{2}, types.Address{7}, types.Address{9}
	rotating, genericValid := types.Address{3}, types.Address{4}
	snapshot := PlannerRuntimeSnapshot{
		KeyFiles: map[string]string{
			key.String(): "key.key", valid.String(): "valid.key", htlc.String(): "htlc.key",
			rotating.String(): "rotating.key", genericValid.String(): "generic.key",
		},
		KeyTypes: map[string]string{
			key.String(): "ed25519", valid.String(): "ed25519", htlc.String(): "aplane.htlc.v1",
			rotating.String(): rotatingkey.RotatingTripleWotscV1, genericValid.String(): "test.self-valid.v1",
		},
		KeyMetadata: map[string]PlannerKeyMetadata{
			key.String():          {Category: keys.CategoryEd25519, ValidRekeyTarget: true},
			valid.String():        {Category: keys.CategoryEd25519, ValidRekeyTarget: true},
			htlc.String():         {Category: keys.CategoryGenericLsig},
			rotating.String():     {Category: keys.CategoryRotatingLsig},
			genericValid.String(): {Category: keys.CategoryGenericLsig, ValidRekeyTarget: true},
		},
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
	rekey := func(sender, target types.Address) types.Transaction {
		txn := testnetPaymentTransaction(t, sender.String(), sender.String(), 0)
		txn.Fee = 1_000
		txn.RekeyTo = target
		return txn
	}
	const (
		invalid    = "invalid" // the valid_rekey_target invariant refuses
		allRekeys  = "all"     // reject_all_rekeys refuses
		foreignOut = "foreign" // reject_foreign_rekey refuses
		allowed    = ""        // review
	)
	held := txnreview.RekeyTransfersText + "\n   " + txnreview.RekeyHeldText
	self := txnreview.RekeyToOwnAddressText + "\n   " + txnreview.RekeyOwnAddressHeldText
	lost := txnreview.RekeyTransfersText + "\n   " + txnreview.RekeyLoseControlText
	type rekeyCase struct {
		name    string
		rekeys  policy.SignerRekeys
		sender  types.Address
		target  types.Address
		listed  bool
		want    string
		warning string // the review's rekey warning; "" skips the check
	}
	cases := []rekeyCase{
		{"reject_all_rekeys/foreign", policy.RekeysRejectAll, key, foreign, false, allRekeys, ""},
		{"reject_all_rekeys/held valid", policy.RekeysRejectAll, key, valid, false, allRekeys, ""},
		{"reject_all_rekeys/held not valid", policy.RekeysRejectAll, key, htlc, false, invalid, ""},
		{"reject_foreign_rekey/foreign", policy.RekeysRejectForeign, key, foreign, false, foreignOut, ""},
		{"reject_foreign_rekey/listed foreign", policy.RekeysRejectForeign, key, foreign, true, allowed, ""},
		{"reject_foreign_rekey/held valid", policy.RekeysRejectForeign, key, valid, false, allowed, held},
		{"reject_foreign_rekey/held not valid", policy.RekeysRejectForeign, key, htlc, false, invalid, ""},
		{"reject_foreign_rekey/listed held not valid", policy.RekeysRejectForeign, key, htlc, true, invalid, ""},
		{"allow_rekeys/foreign", policy.RekeysAllow, key, foreign, false, allowed, lost},
		{"allow_rekeys/held valid", policy.RekeysAllow, key, valid, false, allowed, held},
		{"allow_rekeys/held not valid", policy.RekeysAllow, key, htlc, false, invalid, ""},
		{"allow_rekeys/listed held not valid", policy.RekeysAllow, key, htlc, true, invalid, ""},
		// An account back to its own address, under every setting.
		{"reject_all_rekeys/ed25519 to itself", policy.RekeysRejectAll, key, key, false, allRekeys, ""},
		{"reject_foreign_rekey/ed25519 to itself", policy.RekeysRejectForeign, key, key, false, allowed, self},
		{"allow_rekeys/ed25519 to itself", policy.RekeysAllow, key, key, false, allowed, self},
		{"reject_foreign_rekey/generic recording true to itself", policy.RekeysRejectForeign, genericValid, genericValid, false, allowed, self},
		{"allow_rekeys/generic recording true to itself", policy.RekeysAllow, genericValid, genericValid, false, allowed, self},
		{"reject_all_rekeys/foreign account to itself", policy.RekeysRejectAll, foreign, foreign, false, allRekeys, ""},
		{"reject_foreign_rekey/foreign account to itself", policy.RekeysRejectForeign, foreign, foreign, false, foreignOut, ""},
	}
	for _, rekeys := range []policy.SignerRekeys{policy.RekeysRejectAll, policy.RekeysRejectForeign, policy.RekeysAllow} {
		cases = append(cases,
			rekeyCase{string(rekeys) + "/rotating to itself", rekeys, rotating, rotating, false, invalid, ""},
			rekeyCase{string(rekeys) + "/generic recording false to itself", rekeys, htlc, htlc, false, invalid, ""},
		)
	}
	for _, tc := range cases {
		for _, auto := range []bool{false, true} {
			mode := "manual"
			if auto {
				mode = "auto"
			}
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				txns := []types.Transaction{rekey(tc.sender, tc.target)}
				var warnings []signerapproval.Violation
				var console strings.Builder
				prompted, approvalCalls := false, 0
				approval := &ApprovalService{
					UserAutoApprove:               &auto,
					GenerateTxnDescriptionFromTxn: func(types.Transaction) string { return "txn" },
					KnownAddresses:                func() map[string]bool { return knownAddressesFromSnapshot(snapshot) },
					HasClient:                     func() bool { return true },
					RequestSigningApprovalContext: func(_ context.Context, _, _, _, _ string, _, _ uint64, v []signerapproval.Violation, _ time.Duration) (bool, error) {
						prompted = true
						warnings = v
						return true, nil
					},
				}
				svc := &Service{
					Approval: approval, PolicyFor: fixedPolicy(shipped(tc.rekeys)),
					Planner: &Planner{Snapshot: func() PlannerRuntimeSnapshot { return snapshot }},
				}
				var logged string
				in := gateInput{
					AllTxns: txns, EvalCount: 1, AuthKeys: []string{tc.sender.String()},
					KnownAddresses: knownAddressesFromSnapshot(snapshot),
					LogRejection:   func(reason string) { logged = reason },
					RequestOperatorApproval: func(ctx context.Context, rule string) *ServiceError {
						approvalCalls++
						return approval.requestSingleTxnApprovalWithContext(ctx, "", signerapi.SignRequest{AuthAddress: tc.sender.String()}, txns, txns, "", 0, 0, rule, nil)
					},
				}
				if tc.listed {
					in.ListedRekeyTargets = map[int]map[string]bool{0: {tc.target.String(): true}}
				}
				rule, err := svc.runApprovalGates(context.Background(), in, &stringConsole{&console})
				if tc.want != allowed {
					wantKind := ErrorForbidden
					if tc.want == invalid {
						wantKind = ErrorRekeyTargetNotValid
					}
					if err == nil || err.Kind != wantKind || err.HTTPStatus() != 403 || approvalCalls != 0 {
						t.Fatalf("error = %v, approval calls = %d; want a %s refusal before approval", err, approvalCalls, wantKind)
					}
					var want string
					switch tc.want {
					case invalid:
						want = "transaction 1: " + rekeyTargetNotValid(tc.target.String(), snapshot.KeyTypes[tc.target.String()]).Message
						if err.Message != want || logged != auditSignerInvariant+want {
							t.Fatalf("error = %q, audit = %q; want the rekey target invariant %q", err.Message, logged, want)
						}
						return
					case allRekeys:
						want = "[" + policy.RejectAllRekeysRuleID + "]"
					case foreignOut:
						want = "[" + policy.RejectForeignRekeyRuleID + "]"
					}
					if !strings.HasPrefix(err.Message, "policy engine rejected request: txn 1: "+want) || strings.Contains(err.Message, signerapi.ErrCodeRekeyTargetNotValid) {
						t.Fatalf("error = %q, want the policy rule %s", err.Message, want)
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
				if tc.warning != "" && warnings[0].Message != tc.warning {
					t.Fatalf("rekey warning = %q, want %q", warnings[0].Message, tc.warning)
				}
			})
		}
	}
}

// stringConsole records what the gates print.
type stringConsole struct{ b *strings.Builder }

func (c *stringConsole) Printf(format string, args ...any) { fmt.Fprintf(c.b, format, args...) }
func (c *stringConsole) Println(args ...any)               { fmt.Fprintln(c.b, args...) }
func (c *stringConsole) Sync()                             {}
