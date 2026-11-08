// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/asaset"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
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

// LintContext is what the hard transaction rules know about this signer.
type LintContext struct {
	// KnownAddresses are the addresses this signer identity holds. Nil treats
	// every rekey target as foreign.
	KnownAddresses map[string]bool
	// ProtocolRekeyTargets are rekeys the signer issued itself (a rotation's
	// next stage). The rekey setting never rejects them, or reject_all_rekeys
	// would stop a rotating account from spending.
	ProtocolRekeyTargets map[string]bool
}

// CheckTxnPolicyLints evaluates hard transaction-level policy rules with
// signer-local key awareness. knownAddresses is the set of addresses held by
// the current signer identity; nil treats every rekey target as foreign.
func CheckTxnPolicyLints(txn types.Transaction, cfg *Config, knownAddresses map[string]bool) []LintViolation {
	return CheckTxnPolicyLintsIn(txn, cfg, LintContext{KnownAddresses: knownAddresses})
}

// CheckTxnPolicyLintsIn is CheckTxnPolicyLints with a full LintContext.
func CheckTxnPolicyLintsIn(txn types.Transaction, cfg *Config, ctx LintContext) []LintViolation {
	if cfg == nil {
		return nil
	}

	// The transaction type verdict runs first and alone: a rejected type
	// never reaches the other rules, so the rejection names the type.
	if cfg.VerdictForType(txn.Type) == TransactionTypeReject {
		return []LintViolation{{
			RuleID:   TransactionTypeRuleID(string(txn.Type)),
			Scope:    "txn",
			TxnIndex: -1,
			Message:  fmt.Sprintf("%s transactions are rejected by policy", txn.Type),
		}}
	}

	var violations []LintViolation
	facts := txeffects.Inspect(txn)

	if violation, ok := rekeyViolation(txn, facts, cfg, ctx); ok {
		violations = append(violations, violation)
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

	violations = append(violations, maxAmountThresholds(cfg).check(txn, cfg)...)

	return violations
}

func formatASALimitAmount(cfg *Config, network string, assetID uint64, raw uint64) string {
	if cfg != nil && cfg.FormatASAAmount != nil {
		if formatted, ok := cfg.FormatASAAmount(network, assetID, raw); ok && formatted != "" {
			return formatted
		}
	}
	return fmt.Sprintf("%d base units", raw)
}

func formatAlgoAmount(microAlgos uint64) string {
	return asaset.FormatUnits(microAlgos, 6) + " ALGO"
}

func networkFromGenesisHash(genesisHash types.Digest, resolver apconfig.GenesisHashNetworkResolver) string {
	network, ok := resolver.NetworkForGenesisHashBytes(genesisHash[:])
	if !ok {
		return ""
	}
	return network
}

// rekeyViolation applies the signer's rekey setting. It only rejects; what it
// lets through goes on to the rest of policy. The cosigner role judges rekeys
// with its own rules, and the signer's own protocol rekeys are never rejected.
func rekeyViolation(txn types.Transaction, facts txeffects.Facts, cfg *Config, ctx LintContext) (LintViolation, bool) {
	target := txn.RekeyTo.String()
	if !facts.Has(txeffects.EffectRekey) || cfg.Role == noderole.RoleCosigner || ctx.ProtocolRekeyTargets[target] {
		return LintViolation{}, false
	}
	switch cfg.Rekeys {
	case RekeysAllow:
		return LintViolation{}, false
	case RekeysRejectForeign:
		if ctx.KnownAddresses[target] {
			return LintViolation{}, false
		}
		return LintViolation{
			RuleID: RejectForeignRekeyRuleID, Scope: "txn", TxnIndex: -1,
			Message: "foreign rekey transactions are rejected by policy",
		}, true
	default:
		// reject_all_rekeys, or a Config never given a setting.
		return LintViolation{
			RuleID: RejectAllRekeysRuleID, Scope: "txn", TxnIndex: -1,
			Message: "rekey transactions are rejected by policy (rekeys: reject_all_rekeys)",
		}, true
	}
}
