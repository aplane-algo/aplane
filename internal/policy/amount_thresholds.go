// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// amountThresholds is one family of per-network transfer amount thresholds:
// the hard max_* limits or the review_* thresholds. Both families share one
// evaluation and differ only in rule IDs and wording.
type amountThresholds struct {
	algo                 map[string]uint64
	asa                  map[string]map[uint64]uint64
	unknownGenesisRuleID string
	algoExceededRuleID   string
	asaExceededRuleID    string
	limitLabel           string // the threshold's name in "exceeds <label> <amount>"
	algoUnknownSubject   string // what cannot be evaluated for an unknown network
	asaUnknownSubject    string
}

func maxAmountThresholds(cfg *Config) amountThresholds {
	return amountThresholds{
		algo:                 cfg.MaxAlgoPayments,
		asa:                  cfg.MaxASAAmounts,
		unknownGenesisRuleID: UnknownGenesisHashRuleID,
		algoExceededRuleID:   MaxAlgoPaymentExceededRuleID,
		asaExceededRuleID:    MaxASAAmountExceededRuleID,
		limitLabel:           "policy max",
		algoUnknownSubject:   "ALGO payment policy limit",
		asaUnknownSubject:    "ASA policy limits",
	}
}

func reviewAmountThresholds(cfg *Config) amountThresholds {
	return amountThresholds{
		algo:                 cfg.ReviewAlgoPayments,
		asa:                  cfg.ReviewASAAmounts,
		unknownGenesisRuleID: ReviewUnknownGenesisHashRuleID,
		algoExceededRuleID:   ReviewAlgoPaymentExceededRuleID,
		asaExceededRuleID:    ReviewASAAmountExceededRuleID,
		limitLabel:           "review threshold",
		algoUnknownSubject:   "ALGO payment review threshold",
		asaUnknownSubject:    "ASA transfer review thresholds",
	}
}

// check returns the violations txn triggers against these thresholds. A
// transfer on a network the genesis hash does not resolve to is a violation,
// so a threshold can never be skipped by an unrecognized network.
func (t amountThresholds) check(txn types.Transaction, cfg *Config) []LintViolation {
	var violations []LintViolation
	add := func(ruleID, message string) {
		violations = append(violations, LintViolation{RuleID: ruleID, Scope: "txn", TxnIndex: -1, Message: message})
	}
	switch {
	case txn.Type == types.PaymentTx && len(t.algo) > 0:
		network := networkFromGenesisHash(txn.GenesisHash, cfg.GenesisHashResolver)
		if network == "" {
			add(t.unknownGenesisRuleID, fmt.Sprintf("cannot evaluate %s for unknown genesis hash %x", t.algoUnknownSubject, txn.GenesisHash[:]))
		} else if limit := t.algo[network]; limit > 0 && txn.Amount > types.MicroAlgos(limit) {
			add(t.algoExceededRuleID, fmt.Sprintf("payment amount %s exceeds %s %s on %s",
				formatAlgoAmount(uint64(txn.Amount)), t.limitLabel, formatAlgoAmount(limit), network))
		}
	case txn.Type == types.AssetTransferTx && len(t.asa) > 0:
		network := networkFromGenesisHash(txn.GenesisHash, cfg.GenesisHashResolver)
		if network == "" {
			add(t.unknownGenesisRuleID, fmt.Sprintf("cannot evaluate %s for unknown genesis hash %x", t.asaUnknownSubject, txn.GenesisHash[:]))
		} else if limit, ok := t.asa[network][uint64(txn.XferAsset)]; ok && txn.AssetAmount > limit {
			assetID := uint64(txn.XferAsset)
			add(t.asaExceededRuleID, fmt.Sprintf("asset transfer amount %s exceeds %s %s on %s",
				formatASALimitAmount(cfg, network, assetID, txn.AssetAmount), t.limitLabel,
				formatASALimitAmount(cfg, network, assetID, limit), network))
		}
	}
	return violations
}
