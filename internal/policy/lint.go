// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"strings"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/txeffects"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// LintViolation is a machine-readable hard policy rejection.
type LintViolation struct {
	RuleID   string
	Scope    string // "txn" or "group"
	Message  string
	TxnIndex int // 0-based; -1 when not applicable
}

// ErrorString renders the violation for logs and user-visible errors.
func (v LintViolation) ErrorString() string {
	if v.TxnIndex >= 0 {
		return fmt.Sprintf("txn %d: [%s] %s", v.TxnIndex+1, v.RuleID, v.Message)
	}
	return fmt.Sprintf("[%s] %s", v.RuleID, v.Message)
}

// JoinLintViolations joins violations into a single readable string.
func JoinLintViolations(vs []LintViolation) string {
	if len(vs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(vs))
	for _, v := range vs {
		parts = append(parts, v.ErrorString())
	}
	return strings.Join(parts, "; ")
}

// CheckGroupPolicyLints evaluates hard group-level policy rules.
func CheckGroupPolicyLints(txns []types.Transaction, cfg *Config) []LintViolation {
	_ = txns
	_ = cfg
	return nil
}

// CheckTxnPolicyLints evaluates hard transaction-level policy rules.
func CheckTxnPolicyLints(txn types.Transaction, sender string, cfg *Config) []LintViolation {
	return CheckTxnPolicyLintsWithKnownAddresses(txn, sender, cfg, nil)
}

// CheckTxnPolicyLintsWithKnownAddresses evaluates hard transaction-level
// policy rules with signer-local key awareness. knownAddresses is the set of
// addresses held by the current signer identity.
func CheckTxnPolicyLintsWithKnownAddresses(txn types.Transaction, sender string, cfg *Config, knownAddresses map[string]bool) []LintViolation {
	_ = sender
	if cfg == nil {
		return nil
	}

	var violations []LintViolation
	facts := txeffects.Inspect(txn)

	if cfg.RejectForeignRekey && facts.Has(txeffects.EffectRekey) && !knownAddresses[txn.RekeyTo.String()] {
		violations = append(violations, LintViolation{
			RuleID:   RejectForeignRekeyRuleID,
			Scope:    "txn",
			TxnIndex: -1,
			Message:  "foreign rekey transactions are rejected by policy",
		})
	}

	if cfg.RejectCloseRemainder && facts.Has(txeffects.EffectClose) {
		violations = append(violations, LintViolation{
			RuleID:   RejectCloseRemainderRuleID,
			Scope:    "txn",
			TxnIndex: -1,
			Message:  "close remainder transactions are rejected by policy",
		})
	}

	if cfg.RejectAssetClose && facts.Has(txeffects.EffectAssetClose) {
		violations = append(violations, LintViolation{
			RuleID:   RejectAssetCloseRuleID,
			Scope:    "txn",
			TxnIndex: -1,
			Message:  "asset close transactions are rejected by policy",
		})
	}

	if cfg.RejectClawback && facts.Has(txeffects.EffectClawback) && txn.AssetSender != txn.Sender {
		violations = append(violations, LintViolation{
			RuleID:   RejectClawbackRuleID,
			Scope:    "txn",
			TxnIndex: -1,
			Message:  "ASA clawback transactions are rejected by policy",
		})
	}

	if cfg.MaxFeeMicroAlgos > 0 && uint64(txn.Fee) > cfg.MaxFeeMicroAlgos {
		violations = append(violations, LintViolation{
			RuleID:   MaxFeeExceededRuleID,
			Scope:    "txn",
			TxnIndex: -1,
			Message:  fmt.Sprintf("transaction fee %d exceeds policy max %d microAlgos", txn.Fee, cfg.MaxFeeMicroAlgos),
		})
	}

	if len(cfg.MaxAlgoPayments) > 0 && txn.Type == types.PaymentTx {
		network := networkFromGenesisHash(txn.GenesisHash, cfg.GenesisHashResolver)
		if network == "" {
			violations = append(violations, LintViolation{
				RuleID:   UnknownGenesisHashRuleID,
				Scope:    "txn",
				TxnIndex: -1,
				Message:  fmt.Sprintf("cannot evaluate ALGO payment policy limit for unknown genesis hash %x", txn.GenesisHash[:]),
			})
		} else if maxAmount := cfg.MaxAlgoPayments[network]; maxAmount > 0 && txn.Amount > types.MicroAlgos(maxAmount) {
			violations = append(violations, LintViolation{
				RuleID:   MaxAlgoPaymentExceededRuleID,
				Scope:    "txn",
				TxnIndex: -1,
				Message:  fmt.Sprintf("payment amount %s exceeds policy max %s on %s", formatAlgoAmount(uint64(txn.Amount)), formatAlgoAmount(maxAmount), network),
			})
		}
	}

	if len(cfg.MaxASAAmounts) > 0 && txn.Type == types.AssetTransferTx {
		network := networkFromGenesisHash(txn.GenesisHash, cfg.GenesisHashResolver)
		if network == "" {
			violations = append(violations, LintViolation{
				RuleID:   UnknownGenesisHashRuleID,
				Scope:    "txn",
				TxnIndex: -1,
				Message:  fmt.Sprintf("cannot evaluate ASA policy limits for unknown genesis hash %x", txn.GenesisHash[:]),
			})
		} else if limits := cfg.MaxASAAmounts[network]; len(limits) > 0 {
			if maxAmount, ok := limits[uint64(txn.XferAsset)]; ok && txn.AssetAmount > maxAmount {
				actualDisplay := formatASALimitAmount(cfg, network, uint64(txn.XferAsset), txn.AssetAmount)
				maxDisplay := formatASALimitAmount(cfg, network, uint64(txn.XferAsset), maxAmount)
				violations = append(violations, LintViolation{
					RuleID:   MaxASAAmountExceededRuleID,
					Scope:    "txn",
					TxnIndex: -1,
					Message:  fmt.Sprintf("asset transfer amount %s exceeds policy max %s on %s", actualDisplay, maxDisplay, network),
				})
			}
		}
	}

	return violations
}

func formatASALimitAmount(cfg *Config, network string, assetID uint64, raw uint64) string {
	if cfg != nil && cfg.FormatASAAmount != nil {
		if formatted, ok := cfg.FormatASAAmount(network, assetID, raw); ok && formatted != "" {
			return formatted
		}
	}
	return fmt.Sprintf("%d", raw)
}

func formatAlgoAmount(microAlgos uint64) string {
	digits := fmt.Sprintf("%d", microAlgos)
	if len(digits) <= 6 {
		digits = strings.Repeat("0", 6-len(digits)+1) + digits
	}
	intPart := digits[:len(digits)-6]
	fracPart := strings.TrimRight(digits[len(digits)-6:], "0")
	if fracPart == "" {
		return intPart + " ALGO"
	}
	return intPart + "." + fracPart + " ALGO"
}

func networkFromGenesisHash(genesisHash types.Digest, resolver apconfig.GenesisHashNetworkResolver) string {
	network, ok := resolver.NetworkForGenesisHashBytes(genesisHash[:])
	if !ok {
		return ""
	}
	return network
}

// CheckTxnPolicyEngine collapses structured transaction violations into one error.
func CheckTxnPolicyEngine(txn types.Transaction, sender string, cfg *Config) error {
	violations := CheckTxnPolicyLints(txn, sender, cfg)
	if len(violations) == 0 {
		return nil
	}
	return fmt.Errorf("%s", JoinLintViolations(violations))
}
