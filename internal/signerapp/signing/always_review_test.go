// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"encoding/base64"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/policy"
)

func TestEvaluateAlwaysReviewRulesUsesKeyOverride(t *testing.T) {
	enabled := true
	authKey := types.Address{9}.String()
	cfg, err := (&policy.StoredConfig{
		KeyOverrides: map[string]*policy.StoredConfig{
			authKey: {
				StoredPolicyCore: policy.StoredPolicyCore{AlwaysReviewWarnings: &enabled},
			},
		},
	}).Apply(policy.DefaultConfig())
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: types.Address{1},
			Fee:    types.MicroAlgos(1_000_001),
		},
	}

	ruleID, review := EvaluateAlwaysReviewRules(
		[]types.Transaction{txn},
		1,
		map[int]bool{},
		map[int]bool{},
		cfg,
		[]string{authKey},
		nil,
		nil,
	)
	if !review {
		t.Fatal("EvaluateAlwaysReviewRules() review = false, want true")
	}
	if ruleID != policy.AlwaysReviewWarningsRuleID {
		t.Fatalf("ruleID = %q, want %q", ruleID, policy.AlwaysReviewWarningsRuleID)
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
		policy.DefaultConfig(),
		nil,
		nil,
		nil,
	); review {
		t.Fatal("EvaluateAlwaysReviewRules() review = true, want false")
	}
}

func TestEvaluateAlwaysReviewRulesUsesTransferGuardThreshold(t *testing.T) {
	cfg := &policy.Config{
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
		cfg,
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
	cfg := routingPolicyConfigForSigningTest(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: review_payee
      networks: [testnet]
      sources: ["`+source.String()+`"]
      assets: ["algo"]
      destinations: ["`+dest.String()+`"]
      limits:
        review_above: 10
`)
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
		cfg,
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

func TestEvaluateAlwaysReviewRulesUsesTransferRoutingKeyOverride(t *testing.T) {
	source := types.Address{1}
	dest := types.Address{2}
	authKey := types.Address{9}.String()
	cfg := routingPolicyConfigForSigningTest(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: operator_default
  routes: []
key_overrides:
  `+authKey+`:
    transfer_policy:
      schema_version: 1
      enabled: true
      on_no_route: reject
      routes:
        - id: override_review
          networks: [testnet]
          sources: ["`+source.String()+`"]
          assets: ["algo"]
          destinations: ["`+dest.String()+`"]
          limits:
            review_above: 10
`)
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
		cfg,
		[]string{authKey},
		nil,
		nil,
	)
	if !review {
		t.Fatal("EvaluateAlwaysReviewRules() review = false, want true")
	}
	if ruleID != "transfer_policy:override_review:review_above" {
		t.Fatalf("ruleID = %q, want key override routing review threshold", ruleID)
	}
}

func TestEvaluateAlwaysReviewRulesSkipsTransferRoutingForExemptIndex(t *testing.T) {
	source := types.Address{1}
	dest := types.Address{2}
	cfg := routingPolicyConfigForSigningTest(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: review_payee
      networks: [testnet]
      sources: ["`+source.String()+`"]
      assets: ["algo"]
      destinations: ["`+dest.String()+`"]
      limits:
        review_above: 10
`)
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
		cfg,
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
		cfg, []string{""}, nil, nil,
	); !review {
		t.Fatal("dangerous passthrough: review = false, want true")
	}

	// A benign passthrough leg does not force review.
	plain := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{1}}}
	if _, review := EvaluateAlwaysReviewRules(
		[]types.Transaction{plain}, 1,
		map[int]bool{0: true}, map[int]bool{},
		cfg, []string{""}, nil, nil,
	); review {
		t.Fatal("benign passthrough: review = true, want false")
	}
}
