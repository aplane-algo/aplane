// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package approvalpolicy provides warning-level checks for signer approval
// flows. These warnings are displayed to operators and may be overridden.
package approvalpolicy

import (
	"encoding/hex"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asa"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/txeffects"
)

// Default policy thresholds.
const (
	DefaultMaxFeeMicroAlgos = 1_000_000 // 1 ALGO
)

// Context is what a warning check knows about the signer's own position.
type Context struct {
	// KnownAddresses is the set of addresses the signer holds. A rekey to one
	// of them is still a finding, but it says the signer keeps control instead
	// of warning that control is lost.
	KnownAddresses map[string]bool
	// ProtocolRekeyTargets are rekey targets the signer itself set as part of
	// a signing protocol and proved before approval ran: a rotating account's
	// next stage. A rekey to one of them is the protocol working, not a
	// dangerous field, and produces no finding.
	ProtocolRekeyTargets map[string]bool
}

// CheckTxnWarnings analyzes a transaction for dangerous fields that should be
// shown to the operator. These are warnings only: the operator can still
// approve. knownAddresses is the set of addresses we have signing authority
// for; if the RekeyTo target is in this set, the "lose control" warning is
// suppressed.
func CheckTxnWarnings(txnBytesHex string, knownAddresses map[string]bool) []signerapproval.Violation {
	if txnBytesHex == "" {
		return nil
	}

	txn, err := DecodeTxnFromHex(txnBytesHex)
	if err != nil {
		return nil
	}

	return CheckDecodedTxnWarnings(txn, knownAddresses)
}

// CheckGroupWarnings analyzes each transaction in a group for dangerous
// fields. Returns aggregated warnings prefixed with the transaction index.
func CheckGroupWarnings(txns []types.Transaction, knownAddresses map[string]bool) []signerapproval.Violation {
	return CheckGroupWarningsIn(txns, Context{KnownAddresses: knownAddresses})
}

// CheckGroupWarningsIn is CheckGroupWarnings with a full Context.
func CheckGroupWarningsIn(txns []types.Transaction, ctx Context) []signerapproval.Violation {
	var all []signerapproval.Violation
	for i, txn := range txns {
		for _, v := range CheckDecodedTxnWarningsIn(txn, ctx) {
			v.Field = fmt.Sprintf("Tx %d/%d: %s", i+1, len(txns), v.Field)
			all = append(all, v)
		}
	}
	return all
}

// CheckDecodedTxnWarnings analyzes a decoded transaction for warning-level
// issues. It is the shared warning evaluator used by both request parsing and
// same-package tests.
func CheckDecodedTxnWarnings(txn types.Transaction, knownAddresses map[string]bool) []signerapproval.Violation {
	return CheckDecodedTxnWarningsIn(txn, Context{KnownAddresses: knownAddresses})
}

// CheckDecodedTxnWarningsIn is CheckDecodedTxnWarnings with a full Context.
func CheckDecodedTxnWarningsIn(txn types.Transaction, ctx Context) []signerapproval.Violation {
	var violations []signerapproval.Violation
	facts := txeffects.Inspect(txn)

	if facts.Has(txeffects.EffectRekey) && !ctx.ProtocolRekeyTargets[txn.RekeyTo.String()] {
		rekeyTarget := txn.RekeyTo.String()
		msg := "This transaction will transfer signing authority to another address."
		if ctx.KnownAddresses[rekeyTarget] {
			msg += "\n   You possess the keys for the new address."
		} else {
			msg += "\n   >>> YOU WILL LOSE CONTROL OF THIS ACCOUNT <<<"
		}
		violations = append(violations, signerapproval.Violation{
			Field:    "RekeyTo",
			Value:    rekeyTarget,
			Severity: signerapproval.ViolationSeverityCritical,
			Message:  msg,
		})
	}

	if facts.Has(txeffects.EffectClose) {
		violations = append(violations, signerapproval.Violation{
			Field:    "CloseRemainderTo",
			Value:    txn.CloseRemainderTo.String(),
			Severity: signerapproval.ViolationSeverityCritical,
			Message:  "This transaction will close your account and send ALL remaining ALGO to another address.",
		})
	}

	if facts.Has(txeffects.EffectAssetClose) {
		violations = append(violations, signerapproval.Violation{
			Field:    "AssetCloseTo",
			Value:    txn.AssetCloseTo.String(),
			Severity: signerapproval.ViolationSeverityWarning,
			Message:  "This transaction will send your ENTIRE balance of this asset to another address.",
		})
	}

	if facts.Has(txeffects.EffectClawback) && txn.AssetSender != txn.Sender {
		violations = append(violations, signerapproval.Violation{
			Field:    "AssetSender",
			Value:    txn.AssetSender.String(),
			Severity: signerapproval.ViolationSeverityWarning,
			Message:  "CLAWBACK: This transaction will move funds from another account using your clawback authority.",
		})
	}

	if txn.Type == types.ApplicationCallTx {
		switch txn.OnCompletion {
		case types.DeleteApplicationOC:
			violations = append(violations, signerapproval.Violation{
				Field:    "OnCompletion",
				Value:    "DeleteApplication",
				Severity: signerapproval.ViolationSeverityWarning,
				Message:  "This transaction will DELETE the application.",
			})
		case types.ClearStateOC:
			violations = append(violations, signerapproval.Violation{
				Field:    "OnCompletion",
				Value:    "ClearState",
				Severity: signerapproval.ViolationSeverityWarning,
				Message:  "This transaction will force-clear your local state for the application.",
			})
		case types.UpdateApplicationOC:
			violations = append(violations, signerapproval.Violation{
				Field:    "OnCompletion",
				Value:    "UpdateApplication",
				Severity: signerapproval.ViolationSeverityWarning,
				Message:  "This transaction will REPLACE the application's approval and clear-state programs.",
			})
		}
	}

	// Asset creation (ConfigAsset 0) is routine; reconfiguring or destroying
	// an existing asset changes who controls it, permanently where a role is
	// cleared.
	if txn.Type == types.AssetConfigTx && txn.ConfigAsset != 0 {
		if txn.AssetParams == (types.AssetParams{}) {
			violations = append(violations, signerapproval.Violation{
				Field:    "ConfigAsset",
				Value:    fmt.Sprintf("%d", txn.ConfigAsset),
				Severity: signerapproval.ViolationSeverityCritical,
				Message:  fmt.Sprintf("This transaction will DESTROY asset #%d. The asset ID is retired permanently.", txn.ConfigAsset),
			})
		} else {
			violations = append(violations, signerapproval.Violation{
				Field:    "ConfigAsset",
				Value:    fmt.Sprintf("%d", txn.ConfigAsset),
				Severity: signerapproval.ViolationSeverityWarning,
				Message: fmt.Sprintf("This transaction will RECONFIGURE the authority addresses of asset #%d. A cleared role cannot be restored."+
					"\n   Manager: %s\n   Reserve: %s\n   Freeze: %s\n   Clawback: %s",
					txn.ConfigAsset, assetRoleAddress(txn.AssetParams.Manager), assetRoleAddress(txn.AssetParams.Reserve),
					assetRoleAddress(txn.AssetParams.Freeze), assetRoleAddress(txn.AssetParams.Clawback)),
			})
		}
	}

	if txn.Type == types.AssetFreezeTx {
		action := "UNFREEZE"
		if txn.AssetFrozen {
			action = "FREEZE"
		}
		violations = append(violations, signerapproval.Violation{
			Field:    "FreezeAccount",
			Value:    txn.FreezeAccount.String(),
			Severity: signerapproval.ViolationSeverityWarning,
			Message:  fmt.Sprintf("This transaction will %s the account's holding of asset #%d using your freeze authority.", action, txn.FreezeAsset),
		})
	}

	if uint64(txn.Fee) > DefaultMaxFeeMicroAlgos {
		algoFee := asa.FormatAmountWithDecimals(uint64(txn.Fee), 6)
		violations = append(violations, signerapproval.Violation{
			Field:    "Fee",
			Value:    algoFee + " ALGO",
			Severity: signerapproval.ViolationSeverityWarning,
			Message:  fmt.Sprintf("Transaction fee is unusually high (%s ALGO). Normal fees are ~0.001 ALGO.", algoFee),
		})
	}

	return violations
}

// assetRoleAddress names an asset role address, or its permanent clearing.
func assetRoleAddress(addr types.Address) string {
	if addr.IsZero() {
		return "(cleared)"
	}
	return addr.String()
}

// DecodeTxnFromHex decodes a transaction from hex-encoded bytes. It handles
// both raw msgpack and "TX" prefixed formats.
func DecodeTxnFromHex(txnBytesHex string) (types.Transaction, error) {
	var txn types.Transaction

	if txnBytesHex == "" {
		return txn, fmt.Errorf("empty transaction bytes")
	}

	txnBytes, err := hex.DecodeString(txnBytesHex)
	if err != nil {
		return txn, fmt.Errorf("failed to decode hex: %w", err)
	}

	if len(txnBytes) > 2 && txnBytes[0] == 'T' && txnBytes[1] == 'X' {
		txnBytes = txnBytes[2:]
	}

	if err := msgpack.Decode(txnBytes, &txn); err != nil {
		return txn, fmt.Errorf("failed to decode msgpack: %w", err)
	}

	return txn, nil
}
