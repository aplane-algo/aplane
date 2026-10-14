// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
)

func TestEvaluateAlwaysReviewRulesResolvesPolicyPerKey(t *testing.T) {
	authKey := types.Address{9}.String()
	own := routingPolicyConfigForSigningTest(t, `{"always_review_warnings": true}`)
	def := routingPolicyConfigForSigningTest(t, `{"always_review_warnings": false}`)
	resolver := keyedPolicy(map[string]*policy.Config{authKey: own}, def)

	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: types.Address{1},
			Fee:    types.MicroAlgos(1_000_001),
		},
	}

	ruleID, review := EvaluateAlwaysReviewRules([]types.Transaction{txn}, 1, map[int]bool{}, map[int]bool{}, resolver, []string{authKey}, nil, nil)
	if !review {
		t.Fatal("EvaluateAlwaysReviewRules() review = false, want true")
	}
	if ruleID != policy.AlwaysReviewWarningsRuleID {
		t.Fatalf("ruleID = %q, want %q", ruleID, policy.AlwaysReviewWarningsRuleID)
	}
	if _, review := EvaluateAlwaysReviewRules([]types.Transaction{txn}, 1, map[int]bool{}, map[int]bool{}, resolver, []string{"OTHER"}, nil, nil); review {
		t.Fatal("a key on the default reviewed under the other key's policy")
	}
	// Policy that cannot be resolved forces review.
	if _, review := EvaluateAlwaysReviewRules([]types.Transaction{txn}, 1, map[int]bool{}, map[int]bool{}, keyedPolicy(nil, nil), []string{"OTHER"}, nil, nil); !review {
		t.Fatal("an unresolvable policy did not force review")
	}
}

func TestEvaluateAlwaysReviewRulesUsesTransactionTypeVerdict(t *testing.T) {
	cfg := routingPolicyConfigForSigningTest(t, `{"transaction_types": {"*": "allow", "keyreg": "review"}}`)
	keyreg := types.Transaction{Type: types.KeyRegistrationTx, Header: types.Header{Sender: types.Address{1}}}
	ruleID, review := EvaluateAlwaysReviewRules([]types.Transaction{keyreg}, 1, map[int]bool{}, map[int]bool{}, fixedPolicy(cfg), nil, nil, nil)
	if !review || ruleID != policy.TransactionTypeRuleID("keyreg") {
		t.Fatalf("EvaluateAlwaysReviewRules(keyreg) = %q, %v; want transaction_type:keyreg review", ruleID, review)
	}
	pay := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{1}}}
	if _, review := EvaluateAlwaysReviewRules([]types.Transaction{pay}, 1, map[int]bool{}, map[int]bool{}, fixedPolicy(cfg), nil, nil, nil); review {
		t.Fatal("an allowed type was reviewed")
	}
	// A reviewed type on a foreign slot is not this signer's verdict.
	if _, review := EvaluateAlwaysReviewRules([]types.Transaction{keyreg}, 1, map[int]bool{}, map[int]bool{0: true}, fixedPolicy(cfg), nil, nil, nil); review {
		t.Fatal("a foreign slot was judged by the type gate")
	}
}

func TestEvaluateAlwaysReviewRulesIgnoresDisabledPolicy(t *testing.T) {
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: types.Address{1},
			Fee:    types.MicroAlgos(1_000_001),
		},
	}

	if _, review := EvaluateAlwaysReviewRules(
		[]types.Transaction{txn},
		1,
		map[int]bool{},
		map[int]bool{},
		fixedPolicy(policy.DefaultConfig()),
		nil,
		nil,
		nil,
	); review {
		t.Fatal("EvaluateAlwaysReviewRules() review = true, want false")
	}
}

func TestEvaluateAlwaysReviewRulesUsesTransferGuardThreshold(t *testing.T) {
	cfg := &policy.Config{
		TransactionTypes: policytest.AllowAllTypes(),
		ReviewASAAmounts: map[string]map[uint64]uint64{
			"testnet": {10458941: 500_000_000},
		},
		GenesisHashResolver: apconfig.DefaultGenesisHashNetworkResolver(),
	}
	txn := types.Transaction{
		Header: types.Header{
			Sender:      types.Address{1},
			GenesisHash: testAlwaysReviewGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		Type: types.AssetTransferTx,
		AssetTransferTxnFields: types.AssetTransferTxnFields{
			XferAsset:   10458941,
			AssetAmount: 500_000_001,
		},
	}

	ruleID, review := EvaluateAlwaysReviewRules(
		[]types.Transaction{txn},
		1,
		map[int]bool{},
		map[int]bool{},
		fixedPolicy(cfg),
		nil,
		nil,
		nil,
	)
	if !review {
		t.Fatal("EvaluateAlwaysReviewRules() review = false, want true")
	}
	if ruleID != policy.ReviewASAAmountExceededRuleID {
		t.Fatalf("ruleID = %q, want %q", ruleID, policy.ReviewASAAmountExceededRuleID)
	}
}

func TestEvaluateAlwaysReviewRulesUsesTransferRouting(t *testing.T) {
	source := types.Address{1}
	dest := types.Address{2}
	cfg := routingPolicyConfigForSigningTest(t, `{
  "transfer_policy": {
    "on_no_route": "reject",
    "routes": [
      {
        "id": "review_payee",
        "networks": ["testnet"],
        "sources": ["`+source.String()+`"],
        "assets": ["algo"],
        "destinations": ["`+dest.String()+`"],
        "limits": {"testnet": {"algo": {"review_above": "10"}}}
      }
    ]
  }
}`)
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      source,
			GenesisHash: testAlwaysReviewGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: dest,
			Amount:   11,
		},
	}

	ruleID, review := EvaluateAlwaysReviewRules(
		[]types.Transaction{txn},
		1,
		map[int]bool{},
		map[int]bool{},
		fixedPolicy(cfg),
		nil,
		nil,
		nil,
	)
	if !review {
		t.Fatal("EvaluateAlwaysReviewRules() review = false, want true")
	}
	if ruleID != "transfer_policy:review_payee:review_above" {
		t.Fatalf("ruleID = %q, want transfer routing review threshold", ruleID)
	}
}

func TestEvaluateAlwaysReviewRulesSkipsTransferRoutingForExemptIndex(t *testing.T) {
	source := types.Address{1}
	dest := types.Address{2}
	cfg := routingPolicyConfigForSigningTest(t, `{
  "transfer_policy": {
    "on_no_route": "reject",
    "routes": [
      {
        "id": "review_payee",
        "networks": ["testnet"],
        "sources": ["`+source.String()+`"],
        "assets": ["algo"],
        "destinations": ["`+dest.String()+`"],
        "limits": {"testnet": {"algo": {"review_above": "10"}}}
      }
    ]
  }
}`)
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      source,
			GenesisHash: testAlwaysReviewGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: dest,
			Amount:   11,
		},
	}

	ruleID, review := EvaluateAlwaysReviewRules(
		[]types.Transaction{txn},
		1,
		map[int]bool{},
		map[int]bool{},
		fixedPolicy(cfg),
		nil,
		nil,
		map[int]bool{0: true},
	)
	if review {
		t.Fatalf("EvaluateAlwaysReviewRules() = (%q, true), want no review for routing-exempt index", ruleID)
	}
}

func testAlwaysReviewGenesisDigest(t *testing.T, encoded string) types.Digest {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode genesis hash: %v", err)
	}
	var out types.Digest
	copy(out[:], decoded)
	return out
}

func TestEvaluateAlwaysReviewRulesForcesReviewOnDangerousPassthrough(t *testing.T) {
	cfg := policy.DefaultConfig() // AlwaysReviewWarnings off by default

	rekeyTxn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:  types.Address{1},
			RekeyTo: types.Address{7},
		},
	}
	// Index 0 is a passthrough leg carrying a rekey: review must be forced even
	// though AlwaysReviewWarnings is off (it only governs the signer's own legs).
	if _, review := EvaluateAlwaysReviewRules(
		[]types.Transaction{rekeyTxn}, 1,
		map[int]bool{0: true}, map[int]bool{},
		fixedPolicy(cfg), []string{""}, nil, nil,
	); !review {
		t.Fatal("dangerous passthrough: review = false, want true")
	}

	// A benign passthrough leg does not force review.
	plain := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{1}}}
	if _, review := EvaluateAlwaysReviewRules(
		[]types.Transaction{plain}, 1,
		map[int]bool{0: true}, map[int]bool{},
		fixedPolicy(cfg), []string{""}, nil, nil,
	); review {
		t.Fatal("benign passthrough: review = true, want false")
	}
}

// An asset reconfigure is a warning-level field: under always_review_warnings
// it is reviewed. The policy must allow acfg, or the type gate rejects the
// transaction before warning review runs and the test proves nothing; the
// gate-order case below shows that rejection.
func TestEvaluateAlwaysReviewRulesReviewsAssetReconfigureWarning(t *testing.T) {
	reviewing := routingPolicyConfigForSigningTest(t, `{"always_review_warnings": true, "transaction_types": {"*": "reject", "acfg": "allow"}}`)
	silent := routingPolicyConfigForSigningTest(t, `{"always_review_warnings": false, "transaction_types": {"*": "reject", "acfg": "allow"}}`)
	reconfigure := types.Transaction{
		Type:   types.AssetConfigTx,
		Header: types.Header{Sender: types.Address{1}},
		AssetConfigTxnFields: types.AssetConfigTxnFields{
			ConfigAsset: 31566704,
			AssetParams: types.AssetParams{Manager: types.Address{2}},
		},
	}
	ruleID, review := EvaluateAlwaysReviewRules([]types.Transaction{reconfigure}, 1, map[int]bool{}, map[int]bool{}, fixedPolicy(reviewing), nil, nil, nil)
	if !review || ruleID != policy.AlwaysReviewWarningsRuleID {
		t.Fatalf("EvaluateAlwaysReviewRules(reconfigure) = %q, %v; want always_review_warnings", ruleID, review)
	}
	if _, review := EvaluateAlwaysReviewRules([]types.Transaction{reconfigure}, 1, map[int]bool{}, map[int]bool{}, fixedPolicy(silent), nil, nil, nil); review {
		t.Fatal("a reconfigure was reviewed with always_review_warnings off")
	}

	// With acfg rejected, the gate never reaches the warning review.
	rejecting := routingPolicyConfigForSigningTest(t, `{"always_review_warnings": true, "transaction_types": {"*": "reject"}}`)
	prompted := 0
	_, err := (&Service{PolicyFor: fixedPolicy(rejecting)}).runApprovalGates(context.Background(), gateInput{
		AllTxns: []types.Transaction{reconfigure}, EvalCount: 1,
		RequestOperatorApproval: func(context.Context, string) *ServiceError { prompted++; return nil },
	}, nil)
	if err == nil || err.Kind != ErrorForbidden || !strings.Contains(err.Message, policy.TransactionTypeRuleID("acfg")) || prompted != 0 {
		t.Fatalf("runApprovalGates(acfg rejected) error = %#v prompts %d, want the type rejection before any review", err, prompted)
	}
}

// A type verdict of review sits in the Always Review tier: it prompts even
// when the operator-default tier would have auto-approved.
func TestRunApprovalGatesTypeReviewBeatsAutoApprove(t *testing.T) {
	cfg := routingPolicyConfigForSigningTest(t, `{"transaction_types": {"*": "allow", "keyreg": "review"}}`)
	keyreg := types.Transaction{Type: types.KeyRegistrationTx, Header: types.Header{Sender: types.Address{1}}}
	autoApproved, promptedRule := 0, ""
	ruleID, err := (&Service{PolicyFor: fixedPolicy(cfg)}).runApprovalGates(context.Background(), gateInput{
		AllTxns: []types.Transaction{keyreg}, EvalCount: 1,
		AutoApprove:             func() (string, bool) { autoApproved++; return policy.AutoApproveSelfNoOpTransferRuleID, true },
		RequestOperatorApproval: func(_ context.Context, rule string) *ServiceError { promptedRule = rule; return nil },
	}, nil)
	if err != nil {
		t.Fatalf("runApprovalGates() error = %v", err)
	}
	if want := policy.TransactionTypeRuleID("keyreg"); ruleID != want || promptedRule != want || autoApproved != 0 {
		t.Fatalf("rule %q prompted %q auto-approvals %d, want review under %s with no auto-approval", ruleID, promptedRule, autoApproved, want)
	}
}

// Across the slots of one group, a rejected type rejects the whole request
// even when another slot's type only asks for review.
func TestTypeRejectBeatsReviewAcrossSlots(t *testing.T) {
	cfg := routingPolicyConfigForSigningTest(t, `{"transaction_types": {"*": "allow", "keyreg": "review", "appl": "reject"}}`)
	txns := []types.Transaction{
		{Type: types.KeyRegistrationTx, Header: types.Header{Sender: types.Address{1}}},
		{Type: types.ApplicationCallTx, Header: types.Header{Sender: types.Address{1}}, ApplicationFields: types.ApplicationFields{ApplicationCallTxnFields: types.ApplicationCallTxnFields{ApplicationID: 5}}},
	}
	prompted := 0
	_, err := (&Service{PolicyFor: fixedPolicy(cfg)}).runApprovalGates(context.Background(), gateInput{
		AllTxns: txns, EvalCount: 2,
		RequestOperatorApproval: func(context.Context, string) *ServiceError { prompted++; return nil },
	}, nil)
	if err == nil || err.Kind != ErrorForbidden || !strings.Contains(err.Message, "txn 2: ["+policy.TransactionTypeRuleID("appl")+"]") || prompted != 0 {
		t.Fatalf("runApprovalGates() error = %#v prompts %d, want slot 2 rejected before any review", err, prompted)
	}
}
