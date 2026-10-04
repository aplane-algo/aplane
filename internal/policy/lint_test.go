// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"encoding/base64"
	"strings"
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.RejectForeignRekey {
		t.Fatal("RejectForeignRekey = false, want true")
	}
	if cfg.RejectCloseRemainder {
		t.Fatal("RejectCloseRemainder = true, want false")
	}
	if cfg.RejectAssetClose {
		t.Fatal("RejectAssetClose = true, want false")
	}
	if cfg.RejectClawback {
		t.Fatal("RejectClawback = true, want false")
	}
}

func TestPolicyV1LimitsCompileToConfig(t *testing.T) {
	cfg := routingConfig(t, `{
  "format": "aplane.signer-policy.v1",
  "limits": {"testnet": {
    "algo": {"review_above": "5000000", "reject_above": "10000000"},
    "asa:123": {"review_above": "12", "reject_above": "45"}
  }}
}`)
	if got := cfg.MaxASAAmounts["testnet"][123]; got != 45 {
		t.Fatalf("MaxASAAmounts[testnet][123] = %d, want 45", got)
	}
	if got := cfg.ReviewASAAmounts["testnet"][123]; got != 12 {
		t.Fatalf("ReviewASAAmounts[testnet][123] = %d, want 12", got)
	}
	if got := cfg.MaxAlgoPayments["testnet"]; got != 10_000_000 {
		t.Fatalf("MaxAlgoPayments[testnet] = %d, want 10000000", got)
	}
	if got := cfg.ReviewAlgoPayments["testnet"]; got != 5_000_000 {
		t.Fatalf("ReviewAlgoPayments[testnet] = %d, want 5000000", got)
	}
}

// TestPolicyV1KeyOverridesInheritBase pins that a key override changes only
// the settings it names and inherits the rest from the compiled document.
// v1 overrides carry scalar settings and limits only.
func TestPolicyV1KeyOverridesInheritBase(t *testing.T) {
	allowlistKey := types.Address{1}.String()
	strictKey := types.Address{2}.String()
	cfg := routingConfig(t, `{
  "format": "aplane.signer-policy.v1",
  "reject_close_remainder": false,
  "key_overrides": {
    "`+allowlistKey+`": {"reject_foreign_rekey": false},
    "`+strictKey+`": {"reject_close_remainder": true}
  }
}`)

	allowlist := cfg.ForKey(allowlistKey)
	if allowlist == cfg {
		t.Fatal("ForKey did not return the override config")
	}
	if allowlist.RejectForeignRekey {
		t.Error("allowlist override RejectForeignRekey = true, want false (override applied)")
	}
	if allowlist.RejectCloseRemainder {
		t.Error("allowlist override RejectCloseRemainder = true, want false (inherited from document)")
	}

	strict := cfg.ForKey(strictKey)
	if !strict.RejectForeignRekey {
		t.Error("strict override RejectForeignRekey = false, want true (inherited default)")
	}
	if !strict.RejectCloseRemainder {
		t.Error("strict override RejectCloseRemainder = false, want true (override applied)")
	}

	if got := cfg.ForKey(types.Address{3}.String()); got != cfg {
		t.Error("ForKey for unknown key should return the base config")
	}

	// A differently formatted auth address still selects its override, so
	// formatting cannot bypass a tightening override.
	if got := cfg.ForKey("  " + strings.ToLower(strictKey) + " "); got != strict {
		t.Error("ForKey did not canonicalize a lowercase, padded auth address")
	}
}

func TestCheckTxnPolicyLints(t *testing.T) {
	nonZeroAddr := types.Address{1}

	tests := []struct {
		name       string
		cfg        *Config
		txn        types.Transaction
		wantRuleID string
	}{
		{
			name:       "reject rekey",
			cfg:        &Config{RejectForeignRekey: true},
			txn:        types.Transaction{Header: types.Header{RekeyTo: nonZeroAddr}},
			wantRuleID: "reject_foreign_rekey",
		},
		{
			name:       "reject close remainder",
			cfg:        &Config{RejectCloseRemainder: true},
			txn:        types.Transaction{PaymentTxnFields: types.PaymentTxnFields{CloseRemainderTo: nonZeroAddr}},
			wantRuleID: "reject_close_remainder",
		},
		{
			name:       "reject asset close",
			cfg:        &Config{RejectAssetClose: true},
			txn:        types.Transaction{AssetTransferTxnFields: types.AssetTransferTxnFields{AssetCloseTo: nonZeroAddr}},
			wantRuleID: "reject_asset_close",
		},
		{
			name:       "reject clawback",
			cfg:        &Config{RejectClawback: true},
			txn:        types.Transaction{Header: types.Header{Sender: types.Address{}}, AssetTransferTxnFields: types.AssetTransferTxnFields{AssetSender: nonZeroAddr}},
			wantRuleID: "reject_clawback",
		},
		{
			name:       "max fee",
			cfg:        &Config{MaxFeeMicroAlgos: 1_000},
			txn:        types.Transaction{Header: types.Header{Fee: types.MicroAlgos(2_000)}},
			wantRuleID: "max_fee_exceeded",
		},
		{
			name:       "max algo payment by network",
			cfg:        &Config{MaxAlgoPayments: map[string]uint64{"testnet": 10_000_000}},
			txn:        types.Transaction{Header: types.Header{GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash)}, Type: types.PaymentTx, PaymentTxnFields: types.PaymentTxnFields{Amount: 11_000_000}},
			wantRuleID: "max_algo_payment_exceeded",
		},
		{
			name:       "max asa amount",
			cfg:        &Config{MaxASAAmounts: map[string]map[uint64]uint64{"testnet": {123: 5}}},
			txn:        types.Transaction{Header: types.Header{GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash)}, Type: types.AssetTransferTx, AssetTransferTxnFields: types.AssetTransferTxnFields{XferAsset: 123, AssetAmount: 6}},
			wantRuleID: "max_asa_amount_exceeded",
		},
		{
			name:       "unknown genesis hash blocks asa policy bypass",
			cfg:        &Config{MaxASAAmounts: map[string]map[uint64]uint64{"testnet": {123: 5}}},
			txn:        types.Transaction{Header: types.Header{GenesisHash: types.Digest{}}, Type: types.AssetTransferTx, AssetTransferTxnFields: types.AssetTransferTxnFields{XferAsset: 123, AssetAmount: 6}},
			wantRuleID: "unknown_genesis_hash",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CheckTxnPolicyLints(tc.txn, tc.cfg, nil)
			if len(got) == 0 {
				t.Fatal("CheckTxnPolicyLints() returned no violations")
			}
			if got[0].RuleID != tc.wantRuleID {
				t.Fatalf("RuleID = %q, want %q", got[0].RuleID, tc.wantRuleID)
			}
		})
	}
}

func TestCheckTxnPolicyLintsAllowsLocalRekeyTarget(t *testing.T) {
	localAddr := types.Address{1}
	txn := types.Transaction{Header: types.Header{RekeyTo: localAddr}}

	got := CheckTxnPolicyLints(
		txn,
		&Config{RejectForeignRekey: true},
		map[string]bool{localAddr.String(): true},
	)
	if len(got) != 0 {
		t.Fatalf("CheckTxnPolicyLints() = %#v, want no local rekey violation", got)
	}
}

func TestCheckTxnPolicyLintsRejectsForeignRekeyTarget(t *testing.T) {
	foreignAddr := types.Address{1}
	txn := types.Transaction{Header: types.Header{RekeyTo: foreignAddr}}

	got := CheckTxnPolicyLints(
		txn,
		&Config{RejectForeignRekey: true},
		map[string]bool{},
	)
	if len(got) != 1 {
		t.Fatalf("len(violations) = %d, want 1", len(got))
	}
	if got[0].RuleID != "reject_foreign_rekey" {
		t.Fatalf("RuleID = %q, want reject_foreign_rekey", got[0].RuleID)
	}
	if !strings.Contains(got[0].Message, "foreign rekey") {
		t.Fatalf("Message = %q, want foreign rekey", got[0].Message)
	}
}

func TestCheckTxnPolicyLintsFormatsMaxAlgoPaymentInAlgo(t *testing.T) {
	cfg := &Config{MaxAlgoPayments: map[string]uint64{"testnet": 10_000_000}}
	txn := types.Transaction{
		Header: types.Header{GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash)},
		Type:   types.PaymentTx,
		PaymentTxnFields: types.PaymentTxnFields{
			Amount: 11_000_000,
		},
	}

	got := CheckTxnPolicyLints(txn, cfg, nil)
	if len(got) != 1 {
		t.Fatalf("len(violations) = %d, want 1", len(got))
	}
	if want := "payment amount 11 ALGO exceeds policy max 10 ALGO on testnet"; got[0].Message != want {
		t.Fatalf("Message = %q, want %q", got[0].Message, want)
	}
}

func TestCheckTxnPolicyLintsUsesASAAmountFormatter(t *testing.T) {
	cfg := &Config{
		MaxASAAmounts: map[string]map[uint64]uint64{
			"testnet": {10458941: 1_000_000},
		},
		FormatASAAmount: func(network string, assetID uint64, raw uint64) (string, bool) {
			if network != "testnet" || assetID != 10458941 {
				return "", false
			}
			switch raw {
			case 2_000_000:
				return "2 USDC (ASA 10458941)", true
			case 1_000_000:
				return "1 USDC (ASA 10458941)", true
			default:
				return "", false
			}
		},
	}
	txn := types.Transaction{
		Header: types.Header{GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash)},
		Type:   types.AssetTransferTx,
		AssetTransferTxnFields: types.AssetTransferTxnFields{
			XferAsset:   10458941,
			AssetAmount: 2_000_000,
		},
	}

	got := CheckTxnPolicyLints(txn, cfg, nil)
	if len(got) != 1 {
		t.Fatalf("len(violations) = %d, want 1", len(got))
	}
	for _, want := range []string{
		"asset transfer amount 2 USDC (ASA 10458941)",
		"policy max 1 USDC (ASA 10458941)",
		"on testnet",
	} {
		if !strings.Contains(got[0].Message, want) {
			t.Fatalf("message %q missing %q", got[0].Message, want)
		}
	}
	if strings.Contains(got[0].Message, "for asset") {
		t.Fatalf("message %q contains redundant asset suffix", got[0].Message)
	}
}

func TestCheckTxnReviewPolicyLints(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *Config
		txn        types.Transaction
		wantRuleID string
	}{
		{
			name:       "review algo payment by network",
			cfg:        &Config{ReviewAlgoPayments: map[string]uint64{"testnet": 5_000_000}},
			txn:        types.Transaction{Header: types.Header{GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash)}, Type: types.PaymentTx, PaymentTxnFields: types.PaymentTxnFields{Amount: 6_000_000}},
			wantRuleID: ReviewAlgoPaymentExceededRuleID,
		},
		{
			name:       "review asa amount by network",
			cfg:        &Config{ReviewASAAmounts: map[string]map[uint64]uint64{"testnet": {10458941: 500_000_000}}},
			txn:        types.Transaction{Header: types.Header{GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash)}, Type: types.AssetTransferTx, AssetTransferTxnFields: types.AssetTransferTxnFields{XferAsset: 10458941, AssetAmount: 500_000_001}},
			wantRuleID: ReviewASAAmountExceededRuleID,
		},
		{
			name:       "unknown genesis hash forces review when asa threshold exists",
			cfg:        &Config{ReviewASAAmounts: map[string]map[uint64]uint64{"testnet": {10458941: 500_000_000}}},
			txn:        types.Transaction{Header: types.Header{GenesisHash: types.Digest{}}, Type: types.AssetTransferTx, AssetTransferTxnFields: types.AssetTransferTxnFields{XferAsset: 10458941, AssetAmount: 1}},
			wantRuleID: ReviewUnknownGenesisHashRuleID,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CheckTxnReviewPolicyLints(tc.txn, tc.cfg)
			if len(got) == 0 {
				t.Fatal("CheckTxnReviewPolicyLints() returned no violations")
			}
			if got[0].RuleID != tc.wantRuleID {
				t.Fatalf("RuleID = %q, want %q", got[0].RuleID, tc.wantRuleID)
			}
		})
	}
}

func testGenesisDigest(t *testing.T, encoded string) types.Digest {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode genesis hash: %v", err)
	}
	var out types.Digest
	copy(out[:], decoded)
	return out
}
