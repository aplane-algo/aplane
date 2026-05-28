// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestExtractTransferMovements(t *testing.T) {
	sender := types.Address{1}
	receiver := types.Address{2}
	closeTo := types.Address{3}
	assetCloseTo := types.Address{4}

	pay := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: sender,
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver:         receiver,
			Amount:           7,
			CloseRemainderTo: closeTo,
		},
	}
	payMovements := ExtractTransferMovements(pay)
	if got := len(payMovements); got != 2 {
		t.Fatalf("payment movements = %d, want 2", got)
	}
	if payMovements[0].Kind != TransferMovementPay || payMovements[0].Amount != 7 || !payMovements[0].AmountKnown {
		t.Fatalf("normal payment movement = %+v", payMovements[0])
	}
	if payMovements[1].Kind != TransferMovementPayClose || payMovements[1].Destination != closeTo || payMovements[1].AmountKnown {
		t.Fatalf("payment close movement = %+v", payMovements[1])
	}

	optin := types.Transaction{
		Type: types.AssetTransferTx,
		Header: types.Header{
			Sender: sender,
		},
		AssetTransferTxnFields: types.AssetTransferTxnFields{
			XferAsset:     123,
			AssetReceiver: sender,
		},
	}
	optinMovements := ExtractTransferMovements(optin)
	if len(optinMovements) != 1 || optinMovements[0].Kind != TransferMovementAxferOptIn {
		t.Fatalf("opt-in movements = %+v", optinMovements)
	}

	clawback := types.Transaction{
		Type: types.AssetTransferTx,
		Header: types.Header{
			Sender: sender,
		},
		AssetTransferTxnFields: types.AssetTransferTxnFields{
			XferAsset:     123,
			AssetSender:   receiver,
			AssetReceiver: closeTo,
			AssetCloseTo:  assetCloseTo,
			AssetAmount:   9,
		},
	}
	clawbackMovements := ExtractTransferMovements(clawback)
	if len(clawbackMovements) != 2 || clawbackMovements[0].Kind != TransferMovementClawback || clawbackMovements[0].AssetSource != receiver {
		t.Fatalf("clawback movements = %+v", clawbackMovements)
	}
	if clawbackMovements[1].Kind != TransferMovementAssetClose || clawbackMovements[1].Source != receiver || clawbackMovements[1].Destination != assetCloseTo {
		t.Fatalf("clawback close movement = %+v", clawbackMovements[1])
	}
}

func TestTransferRoutingEvaluation(t *testing.T) {
	source := types.Address{1}
	dest := types.Address{2}
	other := types.Address{3}
	cfg := routingConfig(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: payroll
      networks: [testnet]
      sources: ["`+source.String()+`"]
      assets: ["algo"]
      destinations: ["`+dest.String()+`"]
      limits:
        review_above: 10
        reject_above: 20
`)
	base := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      source,
			GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: dest,
		},
	}

	allowed := base
	allowed.Amount = 10
	if got := CheckTxnTransferRoutingPolicyLints(allowed, cfg, false); len(got) != 0 {
		t.Fatalf("deny lints below threshold = %+v", got)
	}
	if got := CheckTxnTransferRoutingReviewPolicyLints(allowed, cfg, false); len(got) != 0 {
		t.Fatalf("review lints below threshold = %+v", got)
	}

	review := base
	review.Amount = 11
	if got := CheckTxnTransferRoutingReviewPolicyLints(review, cfg, false); len(got) != 1 || got[0].RuleID != "transfer_policy:payroll:review_above" {
		t.Fatalf("review threshold lints = %+v", got)
	}

	reject := base
	reject.Amount = 21
	if got := CheckTxnTransferRoutingPolicyLints(reject, cfg, false); len(got) != 1 || got[0].RuleID != "transfer_policy:payroll:reject_above" {
		t.Fatalf("reject threshold lints = %+v", got)
	}

	miss := base
	miss.Receiver = other
	if got := CheckTxnTransferRoutingPolicyLints(miss, cfg, false); len(got) != 1 || got[0].RuleID != TransferRoutingRouteMissRuleID {
		t.Fatalf("route miss lints = %+v", got)
	}

	if got := CheckTxnTransferRoutingPolicyLints(miss, cfg, true); len(got) != 0 {
		t.Fatalf("routing-exempt lints = %+v", got)
	}
}

func TestTransferRoutingReviewOnNoRoute(t *testing.T) {
	source := types.Address{1}
	dest := types.Address{2}
	cfg := routingConfig(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: review
  routes: []
`)
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      source,
			GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: dest,
			Amount:   1,
		},
	}
	if got := CheckTxnTransferRoutingPolicyLints(txn, cfg, false); len(got) != 0 {
		t.Fatalf("deny lints = %+v", got)
	}
	if got := CheckTxnTransferRoutingReviewPolicyLints(txn, cfg, false); len(got) != 1 || got[0].RuleID != TransferRoutingRouteMissRuleID {
		t.Fatalf("review lints = %+v", got)
	}
}

func TestTransferRoutingUnknownGenesisHashOnNoRoute(t *testing.T) {
	source := types.Address{1}
	dest := types.Address{2}
	tests := []struct {
		name      string
		onNoRoute string
		check     func(t *testing.T, txn types.Transaction, cfg *Config)
	}{
		{
			name:      "reject",
			onNoRoute: string(TransferOnNoRouteReject),
			check: func(t *testing.T, txn types.Transaction, cfg *Config) {
				t.Helper()
				assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(txn, cfg, false), []string{TransferRoutingUnknownGenesisRuleID})
				assertRoutingRuleIDs(t, CheckTxnTransferRoutingReviewPolicyLints(txn, cfg, false), nil)
			},
		},
		{
			name:      "review",
			onNoRoute: string(TransferOnNoRouteReview),
			check: func(t *testing.T, txn types.Transaction, cfg *Config) {
				t.Helper()
				assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(txn, cfg, false), nil)
				assertRoutingRuleIDs(t, CheckTxnTransferRoutingReviewPolicyLints(txn, cfg, false), []string{TransferRoutingUnknownGenesisRuleID})
			},
		},
		{
			name:      "operator default",
			onNoRoute: string(TransferOnNoRouteOperatorDefault),
			check: func(t *testing.T, txn types.Transaction, cfg *Config) {
				t.Helper()
				assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(txn, cfg, false), nil)
				assertRoutingRuleIDs(t, CheckTxnTransferRoutingReviewPolicyLints(txn, cfg, false), nil)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := routingConfig(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: `+tc.onNoRoute+`
  routes:
    - id: any_algo
      networks: ["*"]
      sources: ["*"]
      assets: ["algo"]
      destinations: ["*"]
`)
			txn := types.Transaction{
				Type: types.PaymentTx,
				Header: types.Header{
					Sender:      source,
					GenesisHash: types.Digest{9},
				},
				PaymentTxnFields: types.PaymentTxnFields{
					Receiver: dest,
					Amount:   1,
				},
			}
			tc.check(t, txn, cfg)
		})
	}
}

func TestTransferRoutingCloseOutIsDeniedBeforeOperatorDefault(t *testing.T) {
	source := types.Address{1}
	dest := types.Address{2}
	closeTo := types.Address{3}
	cfg := routingConfig(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: operator_default
  routes:
    - id: normal_pay
      networks: [testnet]
      sources: ["`+source.String()+`"]
      assets: ["algo"]
      destinations: ["`+dest.String()+`"]
`)
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      source,
			GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver:         dest,
			Amount:           1,
			CloseRemainderTo: closeTo,
		},
	}
	if got := CheckTxnTransferRoutingPolicyLints(txn, cfg, false); len(got) != 1 || got[0].RuleID != TransferRoutingCloseRejectedRuleID {
		t.Fatalf("close rejection lints = %+v", got)
	}
}

func TestTransferRoutingCloseAndClawbackOnNoRouteFallbacks(t *testing.T) {
	source := types.Address{1}
	dest := types.Address{2}
	closeTo := types.Address{3}
	authority := types.Address{4}
	owner := types.Address{5}
	recovery := types.Address{6}
	cfg := routingConfig(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  close_on_no_route: review
  clawback_on_no_route: operator_default
  routes:
    - id: normal_pay
      networks: [testnet]
      sources: ["`+source.String()+`"]
      assets: ["algo"]
      destinations: ["`+dest.String()+`"]
    - id: close_without_allow
      networks: [testnet]
      sources: ["`+source.String()+`"]
      assets: ["algo"]
      destinations: ["`+closeTo.String()+`"]
    - id: clawback_without_match
      networks: [testnet]
      sources: ["`+authority.String()+`"]
      asset_sources: ["`+owner.String()+`"]
      assets: [123]
      destinations: ["`+recovery.String()+`"]
      clawback:
        allow: true
`)
	noRouteClose := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      source,
			GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver:         dest,
			Amount:           1,
			CloseRemainderTo: types.Address{9},
		},
	}
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(noRouteClose, cfg, false), nil)
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingReviewPolicyLints(noRouteClose, cfg, false), []string{TransferRoutingCloseRouteMissRuleID})

	matchedCloseWithoutAllow := noRouteClose
	matchedCloseWithoutAllow.CloseRemainderTo = closeTo
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(matchedCloseWithoutAllow, cfg, false), []string{"transfer_policy:close_without_allow:close_rejected"})

	noRouteClawback := types.Transaction{
		Type: types.AssetTransferTx,
		Header: types.Header{
			Sender:      authority,
			GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		AssetTransferTxnFields: types.AssetTransferTxnFields{
			XferAsset:     123,
			AssetSender:   types.Address{10},
			AssetReceiver: recovery,
			AssetAmount:   1,
		},
	}
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(noRouteClawback, cfg, false), nil)
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingReviewPolicyLints(noRouteClawback, cfg, false), nil)

	ordinaryMiss := noRouteClose
	ordinaryMiss.Receiver = types.Address{11}
	ordinaryMiss.CloseRemainderTo = types.Address{}
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(ordinaryMiss, cfg, false), []string{TransferRoutingRouteMissRuleID})
}

func TestTransferRoutingAddressSetsMatchByNetwork(t *testing.T) {
	source := types.Address{1}
	authority := types.Address{2}
	owner := types.Address{3}
	dest := types.Address{4}
	mainnetOnlyDest := types.Address{5}
	cfg := routingConfig(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  address_sets:
    sources:
      - `+source.String()+`
    receivers:
      testnet:
        - `+dest.String()+`
      mainnet:
        - `+mainnetOnlyDest.String()+`
    owners:
      testnet:
        - `+owner.String()+`
  routes:
    - id: set_pay
      networks: [testnet]
      sources: ["@sources"]
      assets: ["algo"]
      destinations: ["@receivers"]
    - id: set_clawback
      networks: [testnet]
      sources: ["`+authority.String()+`"]
      asset_sources: ["@owners"]
      assets: [123]
      destinations: ["@receivers"]
      clawback:
        allow: true
`)
	pay := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      source,
			GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: dest,
			Amount:   1,
		},
	}
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(pay, cfg, false), nil)
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingReviewPolicyLints(pay, cfg, false), nil)

	wrongNetworkDestination := pay
	wrongNetworkDestination.Receiver = mainnetOnlyDest
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(wrongNetworkDestination, cfg, false), []string{TransferRoutingRouteMissRuleID})

	clawback := types.Transaction{
		Type: types.AssetTransferTx,
		Header: types.Header{
			Sender:      authority,
			GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		AssetTransferTxnFields: types.AssetTransferTxnFields{
			XferAsset:     123,
			AssetSender:   owner,
			AssetReceiver: dest,
			AssetAmount:   1,
		},
	}
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(clawback, cfg, false), nil)
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingReviewPolicyLints(clawback, cfg, false), nil)
}

func TestTransferRoutingAssetSetAndOverlappingThresholds(t *testing.T) {
	source := types.Address{1}
	dest := types.Address{2}
	cfg := routingConfig(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  asset_sets:
    stablecoins:
      testnet: [123]
  routes:
    - id: broad
      networks: [testnet]
      sources: ["*"]
      assets: ["@stablecoins"]
      destinations: ["*"]
      limits:
        reject_above: 100
    - id: narrow
      networks: [testnet]
      sources: ["`+source.String()+`"]
      assets: [123]
      destinations: ["`+dest.String()+`"]
      limits:
        reject_above: 50
`)
	txn := types.Transaction{
		Type: types.AssetTransferTx,
		Header: types.Header{
			Sender:      source,
			GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		AssetTransferTxnFields: types.AssetTransferTxnFields{
			XferAsset:     123,
			AssetReceiver: dest,
			AssetAmount:   60,
		},
	}
	if got := CheckTxnTransferRoutingPolicyLints(txn, cfg, false); len(got) != 1 || got[0].RuleID != "transfer_policy:narrow:reject_above" {
		t.Fatalf("overlapping threshold lints = %+v", got)
	}
}

func TestTransferRoutingLimitsByNetworkOverrideGlobalLimits(t *testing.T) {
	source := types.Address{1}
	dest := types.Address{2}
	cfg := routingConfig(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: tiered_pay
      networks: [testnet, mainnet]
      sources: ["`+source.String()+`"]
      assets: ["algo"]
      destinations: ["`+dest.String()+`"]
      limits:
        review_above: 70
        reject_above: 100
      limits_by_network:
        testnet:
          review_above: 10
          reject_above: 50
`)
	base := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      source,
			GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: dest,
		},
	}

	atReviewThreshold := base
	atReviewThreshold.Amount = 10
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(atReviewThreshold, cfg, false), nil)
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingReviewPolicyLints(atReviewThreshold, cfg, false), nil)

	aboveNetworkReview := base
	aboveNetworkReview.Amount = 11
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(aboveNetworkReview, cfg, false), nil)
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingReviewPolicyLints(aboveNetworkReview, cfg, false), []string{"transfer_policy:tiered_pay:review_above"})

	aboveNetworkReject := base
	aboveNetworkReject.Amount = 51
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(aboveNetworkReject, cfg, false), []string{"transfer_policy:tiered_pay:reject_above"})

	mainnetUsesGlobalReview := base
	mainnetUsesGlobalReview.GenesisHash = testGenesisDigest(t, apconfig.AlgorandMainnetGenesisHash)
	mainnetUsesGlobalReview.Amount = 71
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(mainnetUsesGlobalReview, cfg, false), nil)
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingReviewPolicyLints(mainnetUsesGlobalReview, cfg, false), []string{"transfer_policy:tiered_pay:review_above"})

	mainnetUsesGlobalReject := mainnetUsesGlobalReview
	mainnetUsesGlobalReject.Amount = 101
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(mainnetUsesGlobalReject, cfg, false), []string{"transfer_policy:tiered_pay:reject_above"})
}

func TestTransferRoutingBlockedDestinations(t *testing.T) {
	source := types.Address{1}
	blocked := types.Address{2}
	other := types.Address{3}
	cfg := routingConfig(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  blocked_destinations:
    - `+blocked.String()+`
  routes:
    - id: allow_all_normal
      networks: [testnet]
      sources: ["*"]
      assets: ["*"]
      destinations: ["*"]
    - id: allow_blocked_pay_close
      networks: [testnet]
      sources: ["*"]
      assets: ["algo"]
      destinations: ["`+blocked.String()+`"]
      close:
        allow: true
    - id: allow_blocked_asset_close
      networks: [testnet]
      sources: ["*"]
      assets: [123]
      destinations: ["`+blocked.String()+`"]
      close:
        allow: true
    - id: allow_blocked_clawback
      networks: [testnet]
      sources: ["`+source.String()+`"]
      asset_sources: ["`+other.String()+`"]
      assets: [123]
      destinations: ["`+blocked.String()+`"]
      clawback:
        allow: true
`)
	header := types.Header{
		Sender:      source,
		GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash),
	}
	tests := []struct {
		name string
		txn  types.Transaction
	}{
		{
			name: "payment receiver",
			txn: types.Transaction{
				Type:   types.PaymentTx,
				Header: header,
				PaymentTxnFields: types.PaymentTxnFields{
					Receiver: blocked,
					Amount:   1,
				},
			},
		},
		{
			name: "payment close remainder",
			txn: types.Transaction{
				Type:   types.PaymentTx,
				Header: header,
				PaymentTxnFields: types.PaymentTxnFields{
					Receiver:         other,
					Amount:           1,
					CloseRemainderTo: blocked,
				},
			},
		},
		{
			name: "asset receiver",
			txn: types.Transaction{
				Type:   types.AssetTransferTx,
				Header: header,
				AssetTransferTxnFields: types.AssetTransferTxnFields{
					XferAsset:     123,
					AssetReceiver: blocked,
					AssetAmount:   1,
				},
			},
		},
		{
			name: "asset close",
			txn: types.Transaction{
				Type:   types.AssetTransferTx,
				Header: header,
				AssetTransferTxnFields: types.AssetTransferTxnFields{
					XferAsset:     123,
					AssetReceiver: other,
					AssetAmount:   1,
					AssetCloseTo:  blocked,
				},
			},
		},
		{
			name: "clawback receiver",
			txn: types.Transaction{
				Type:   types.AssetTransferTx,
				Header: header,
				AssetTransferTxnFields: types.AssetTransferTxnFields{
					XferAsset:     123,
					AssetSender:   other,
					AssetReceiver: blocked,
					AssetAmount:   1,
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lints := CheckTxnTransferRoutingPolicyLints(tc.txn, cfg, false)
			if len(lints) != 1 || lints[0].RuleID != TransferRoutingBlockedDestinationRuleID {
				t.Fatalf("blocked destination lints = %+v", lints)
			}
		})
	}
}

func TestTransferRoutingCloseAndClawbackBranches(t *testing.T) {
	source := types.Address{1}
	dest := types.Address{2}
	closeRejected := types.Address{3}
	closeAllowed := types.Address{4}
	authority := types.Address{5}
	owner := types.Address{6}
	otherOwner := types.Address{7}
	recovery := types.Address{8}
	cfg := routingConfig(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: normal_pay
      networks: [testnet]
      sources: ["`+source.String()+`"]
      assets: ["algo"]
      destinations: ["`+dest.String()+`"]
    - id: close_without_allow
      networks: [testnet]
      sources: ["`+source.String()+`"]
      assets: ["algo"]
      destinations: ["`+closeRejected.String()+`"]
    - id: close_with_allow
      networks: [testnet]
      sources: ["`+source.String()+`"]
      assets: ["algo"]
      destinations: ["`+closeAllowed.String()+`"]
      close:
        allow: true
    - id: clawback_recovery
      networks: [testnet]
      sources: ["`+authority.String()+`"]
      asset_sources: ["`+owner.String()+`"]
      assets: [123]
      destinations: ["`+recovery.String()+`"]
      clawback:
        allow: true
`)
	closeRejectedTxn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      source,
			GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver:         dest,
			Amount:           1,
			CloseRemainderTo: closeRejected,
		},
	}
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(closeRejectedTxn, cfg, false), []string{"transfer_policy:close_without_allow:close_rejected"})

	closeAllowedTxn := closeRejectedTxn
	closeAllowedTxn.CloseRemainderTo = closeAllowed
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(closeAllowedTxn, cfg, false), nil)
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingReviewPolicyLints(closeAllowedTxn, cfg, false), nil)

	clawbackAllowed := types.Transaction{
		Type: types.AssetTransferTx,
		Header: types.Header{
			Sender:      authority,
			GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		AssetTransferTxnFields: types.AssetTransferTxnFields{
			XferAsset:     123,
			AssetSender:   owner,
			AssetReceiver: recovery,
			AssetAmount:   1,
		},
	}
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(clawbackAllowed, cfg, false), nil)
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingReviewPolicyLints(clawbackAllowed, cfg, false), nil)

	clawbackRejected := clawbackAllowed
	clawbackRejected.AssetSender = otherOwner
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(clawbackRejected, cfg, false), []string{TransferRoutingClawbackRejectedRuleID})

	clawbackCloseRejected := clawbackAllowed
	clawbackCloseRejected.AssetCloseTo = closeRejected
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(clawbackCloseRejected, cfg, false), []string{TransferRoutingCloseRejectedRuleID})
}

func TestTransferRoutingDisabledRoutesAndNonTransferTransactions(t *testing.T) {
	source := types.Address{1}
	dest := types.Address{2}
	disabled := false
	cfg := routingConfig(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: disabled_pay
      enabled: false
      networks: [testnet]
      sources: ["`+source.String()+`"]
      assets: ["algo"]
      destinations: ["`+dest.String()+`"]
`)
	pay := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      source,
			GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: dest,
			Amount:   1,
		},
	}
	if cfg.TransferPolicy.Routes[0].Enabled != disabled {
		t.Fatalf("route enabled = %v, want %v", cfg.TransferPolicy.Routes[0].Enabled, disabled)
	}
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(pay, cfg, false), []string{TransferRoutingRouteMissRuleID})

	appCall := types.Transaction{
		Type: types.ApplicationCallTx,
		Header: types.Header{
			Sender:      source,
			GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
	}
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(appCall, cfg, false), nil)
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingReviewPolicyLints(appCall, cfg, false), nil)
}

func TestTransferRoutingMultipleMovementsCanEmitMultipleVerdicts(t *testing.T) {
	source := types.Address{1}
	allowed := types.Address{2}
	miss := types.Address{3}
	closeTo := types.Address{4}
	cfg := routingConfig(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: allowed_pay
      networks: [testnet]
      sources: ["`+source.String()+`"]
      assets: ["algo"]
      destinations: ["`+allowed.String()+`"]
`)
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      source,
			GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver:         miss,
			Amount:           1,
			CloseRemainderTo: closeTo,
		},
	}
	assertRoutingRuleIDs(t, CheckTxnTransferRoutingPolicyLints(txn, cfg, false), []string{
		TransferRoutingRouteMissRuleID,
		TransferRoutingCloseRejectedRuleID,
	})
}

func TestTransferRoutingBlockedDestinationPrecedenceAndExemptions(t *testing.T) {
	source := types.Address{1}
	blocked := types.Address{2}
	otherBlocked := types.Address{3}
	cfg := routingConfig(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  blocked_destinations:
    - `+blocked.String()+`
    - `+otherBlocked.String()+`
  routes:
    - id: allow_blocked
      networks: ["*"]
      sources: ["*"]
      assets: ["algo"]
      destinations: ["*"]
    - id: allow_blocked_close
      networks: ["*"]
      sources: ["*"]
      assets: ["algo"]
      destinations: ["`+otherBlocked.String()+`"]
      close:
        allow: true
`)
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      source,
			GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver:         blocked,
			Amount:           1,
			CloseRemainderTo: otherBlocked,
		},
	}
	lints := CheckTxnTransferRoutingPolicyLints(txn, cfg, false)
	if len(lints) != 2 {
		t.Fatalf("blocked destination lints = %+v, want 2", lints)
	}
	for _, lint := range lints {
		if lint.RuleID != TransferRoutingBlockedDestinationRuleID {
			t.Fatalf("blocked destination lint rule ID = %q", lint.RuleID)
		}
	}
	if got := CheckTxnTransferRoutingPolicyLints(txn, cfg, true); len(got) != 0 {
		t.Fatalf("routing-exempt blocked destination lints = %+v", got)
	}

	unknownGenesis := txn
	unknownGenesis.GenesisHash = types.Digest{9}
	lints = CheckTxnTransferRoutingPolicyLints(unknownGenesis, cfg, false)
	if len(lints) != 2 {
		t.Fatalf("unknown-genesis blocked destination lints = %+v, want 2", lints)
	}
	for _, lint := range lints {
		if lint.RuleID != TransferRoutingBlockedDestinationRuleID {
			t.Fatalf("unknown-genesis rule ID = %q, want blocked destination", lint.RuleID)
		}
	}
}

func TestTransferRoutingBlockedDestinationsSkipOptIn(t *testing.T) {
	blocked := types.Address{1}
	cfg := routingConfig(t, `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  blocked_destinations:
    - `+blocked.String()+`
  routes:
    - id: allow_optin
      networks: [testnet]
      sources: ["`+blocked.String()+`"]
      assets: [123]
      destinations: ["self"]
`)
	txn := types.Transaction{
		Type: types.AssetTransferTx,
		Header: types.Header{
			Sender:      blocked,
			GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash),
		},
		AssetTransferTxnFields: types.AssetTransferTxnFields{
			XferAsset:     123,
			AssetReceiver: blocked,
		},
	}
	if got := CheckTxnTransferRoutingPolicyLints(txn, cfg, false); len(got) != 0 {
		t.Fatalf("opt-in blocked destination deny lints = %+v", got)
	}
	if got := CheckTxnTransferRoutingReviewPolicyLints(txn, cfg, false); len(got) != 0 {
		t.Fatalf("opt-in blocked destination review lints = %+v", got)
	}
}

func routingConfig(t *testing.T, raw string) *Config {
	t.Helper()
	stored := parsePolicyYAML(t, raw)
	cfg, err := stored.Apply(DefaultConfig())
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	return cfg
}

func assertRoutingRuleIDs(t *testing.T, got []LintViolation, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("routing rule IDs = %v, want %v", lintRuleIDs(got), want)
	}
	for i, wantRuleID := range want {
		if got[i].RuleID != wantRuleID {
			t.Fatalf("routing rule IDs = %v, want %v", lintRuleIDs(got), want)
		}
	}
}

func lintRuleIDs(lints []LintViolation) []string {
	out := make([]string, 0, len(lints))
	for _, lint := range lints {
		out = append(out, lint.RuleID)
	}
	return out
}
