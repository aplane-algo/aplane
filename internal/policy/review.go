// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// CheckTxnReviewPolicyLints evaluates transaction-level policy rules that
// require operator review after hard-reject policy passes. The transaction
// type verdict runs first so a review names the type rather than a threshold.
func CheckTxnReviewPolicyLints(txn types.Transaction, cfg *Config) []LintViolation {
	if cfg == nil {
		return nil
	}
	if cfg.VerdictForType(txn.Type) == TransactionTypeReview {
		return []LintViolation{{
			RuleID:   TransactionTypeRuleID(string(txn.Type)),
			Scope:    "txn",
			TxnIndex: -1,
			Message:  fmt.Sprintf("%s transactions require operator review by policy", txn.Type),
		}}
	}
	return reviewAmountThresholds(cfg).check(txn, cfg)
}
