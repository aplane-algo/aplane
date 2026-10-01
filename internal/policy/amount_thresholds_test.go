// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	apconfig "github.com/aplane-algo/aplane/internal/config"
)

// TestAmountThresholdViolations pins the rule IDs and messages of both
// threshold families, which share one evaluation.
func TestAmountThresholdViolations(t *testing.T) {
	testnet := testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash)
	unknown := types.Digest{0xab}
	unknownHex := "ab" + strings.Repeat("00", 31)
	payment := func(hash types.Digest) types.Transaction {
		return types.Transaction{
			Header:           types.Header{GenesisHash: hash},
			Type:             types.PaymentTx,
			PaymentTxnFields: types.PaymentTxnFields{Amount: 11_000_000},
		}
	}
	assetTransfer := func(hash types.Digest) types.Transaction {
		return types.Transaction{
			Header:                 types.Header{GenesisHash: hash},
			Type:                   types.AssetTransferTx,
			AssetTransferTxnFields: types.AssetTransferTxnFields{XferAsset: 7, AssetAmount: 2_000_000},
		}
	}
	maxCfg := &Config{
		MaxAlgoPayments: map[string]uint64{"testnet": 10_000_000},
		MaxASAAmounts:   map[string]map[uint64]uint64{"testnet": {7: 1_000_000}},
	}
	reviewCfg := &Config{
		ReviewAlgoPayments: map[string]uint64{"testnet": 10_000_000},
		ReviewASAAmounts:   map[string]map[uint64]uint64{"testnet": {7: 1_000_000}},
	}
	for _, tc := range []struct {
		name    string
		review  bool
		txn     types.Transaction
		ruleID  string
		message string
	}{
		{"max algo exceeded", false, payment(testnet), MaxAlgoPaymentExceededRuleID, "payment amount 11 ALGO exceeds policy max 10 ALGO on testnet"},
		{"max algo unknown network", false, payment(unknown), UnknownGenesisHashRuleID, "cannot evaluate ALGO payment policy limit for unknown genesis hash " + unknownHex},
		{"max asa exceeded", false, assetTransfer(testnet), MaxASAAmountExceededRuleID, "asset transfer amount 2000000 exceeds policy max 1000000 on testnet"},
		{"max asa unknown network", false, assetTransfer(unknown), UnknownGenesisHashRuleID, "cannot evaluate ASA policy limits for unknown genesis hash " + unknownHex},
		{"review algo exceeded", true, payment(testnet), ReviewAlgoPaymentExceededRuleID, "payment amount 11 ALGO exceeds review threshold 10 ALGO on testnet"},
		{"review algo unknown network", true, payment(unknown), ReviewUnknownGenesisHashRuleID, "cannot evaluate ALGO payment review threshold for unknown genesis hash " + unknownHex},
		{"review asa exceeded", true, assetTransfer(testnet), ReviewASAAmountExceededRuleID, "asset transfer amount 2000000 exceeds review threshold 1000000 on testnet"},
		{"review asa unknown network", true, assetTransfer(unknown), ReviewUnknownGenesisHashRuleID, "cannot evaluate ASA transfer review thresholds for unknown genesis hash " + unknownHex},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []LintViolation
			if tc.review {
				got = reviewAmountThresholds(reviewCfg).check(tc.txn, reviewCfg)
			} else {
				got = maxAmountThresholds(maxCfg).check(tc.txn, maxCfg)
			}
			if len(got) != 1 || got[0].RuleID != tc.ruleID || got[0].Message != tc.message {
				t.Fatalf("violations = %#v, want one %s: %q", got, tc.ruleID, tc.message)
			}
		})
	}
}
