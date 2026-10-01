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

	return reviewAmountThresholds(cfg).check(txn, cfg)
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
