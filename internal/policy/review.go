// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// CheckTxnReviewPolicyLints evaluates transaction-level policy rules that
// require operator review after hard-reject policy passes.
func CheckTxnReviewPolicyLints(txn types.Transaction, cfg *Config) []LintViolation {
	if cfg == nil {
		return nil
	}

	var violations []LintViolation

	if txn.Type == types.PaymentTx && len(cfg.ReviewAlgoPayments) > 0 {
		network := networkFromGenesisHash(txn.GenesisHash, cfg.GenesisHashResolver)
		if network == "" {
			violations = append(violations, LintViolation{
				RuleID:   ReviewUnknownGenesisHashRuleID,
				Scope:    "txn",
				TxnIndex: -1,
				Message:  fmt.Sprintf("cannot evaluate ALGO payment review threshold for unknown genesis hash %x", txn.GenesisHash[:]),
			})
		} else if reviewAmount := cfg.ReviewAlgoPayments[network]; reviewAmount > 0 && txn.Amount > types.MicroAlgos(reviewAmount) {
			violations = append(violations, LintViolation{
				RuleID:   ReviewAlgoPaymentExceededRuleID,
				Scope:    "txn",
				TxnIndex: -1,
				Message:  fmt.Sprintf("payment amount %s exceeds review threshold %s on %s", formatAlgoAmount(uint64(txn.Amount)), formatAlgoAmount(reviewAmount), network),
			})
		}
	}

	if txn.Type == types.AssetTransferTx && len(cfg.ReviewASAAmounts) > 0 {
		network := networkFromGenesisHash(txn.GenesisHash, cfg.GenesisHashResolver)
		if network == "" {
			violations = append(violations, LintViolation{
				RuleID:   ReviewUnknownGenesisHashRuleID,
				Scope:    "txn",
				TxnIndex: -1,
				Message:  fmt.Sprintf("cannot evaluate ASA transfer review thresholds for unknown genesis hash %x", txn.GenesisHash[:]),
			})
		} else if limits := cfg.ReviewASAAmounts[network]; len(limits) > 0 {
			if reviewAmount, ok := limits[uint64(txn.XferAsset)]; ok && txn.AssetAmount > reviewAmount {
				actualDisplay := formatASALimitAmount(cfg, network, uint64(txn.XferAsset), txn.AssetAmount)
				reviewDisplay := formatASALimitAmount(cfg, network, uint64(txn.XferAsset), reviewAmount)
				violations = append(violations, LintViolation{
					RuleID:   ReviewASAAmountExceededRuleID,
					Scope:    "txn",
					TxnIndex: -1,
					Message:  fmt.Sprintf("asset transfer amount %s exceeds review threshold %s on %s", actualDisplay, reviewDisplay, network),
				})
			}
		}
	}

	return violations
}

// ValidateTransferGuards rejects transfer guard configurations where a deny
// threshold is below the matching review threshold.
func ValidateTransferGuards(cfg *Config) error {
	if cfg == nil {
		return nil
	}

	for network, reviewAmount := range cfg.ReviewAlgoPayments {
		if reviewAmount == 0 {
			continue
		}
		denyAmount := cfg.MaxAlgoPayments[network]
		if denyAmount > 0 && denyAmount < reviewAmount {
			return fmt.Errorf("max_algo_payments[%s] must be greater than or equal to review_algo_payments[%s]", network, network)
		}
	}

	for network, reviewAmounts := range cfg.ReviewASAAmounts {
		if len(reviewAmounts) == 0 {
			continue
		}
		denyAmounts := cfg.MaxASAAmounts[network]
		for assetID, reviewAmount := range reviewAmounts {
			if reviewAmount == 0 {
				continue
			}
			if denyAmount := denyAmounts[assetID]; denyAmount > 0 && denyAmount < reviewAmount {
				return fmt.Errorf("max_asa_amounts[%s][%d] must be greater than or equal to review_asa_amounts[%s][%d]", network, assetID, network, assetID)
			}
		}
	}

	return nil
}
