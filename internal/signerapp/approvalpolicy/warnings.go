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
)

// Default policy thresholds.
const (
	DefaultMaxFeeMicroAlgos = 1_000_000 // 1 ALGO
)

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
	var all []signerapproval.Violation
	for i, txn := range txns {
		for _, v := range CheckDecodedTxnWarnings(txn, knownAddresses) {
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
	var violations []signerapproval.Violation

	if !txn.RekeyTo.IsZero() {
		rekeyTarget := txn.RekeyTo.String()
		msg := "This transaction will transfer signing authority to another address."
		if knownAddresses[rekeyTarget] {
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

	if !txn.CloseRemainderTo.IsZero() {
		violations = append(violations, signerapproval.Violation{
			Field:    "CloseRemainderTo",
			Value:    txn.CloseRemainderTo.String(),
			Severity: signerapproval.ViolationSeverityCritical,
			Message:  "This transaction will close your account and send ALL remaining ALGO to another address.",
		})
	}

	if !txn.AssetCloseTo.IsZero() {
		violations = append(violations, signerapproval.Violation{
			Field:    "AssetCloseTo",
			Value:    txn.AssetCloseTo.String(),
			Severity: signerapproval.ViolationSeverityWarning,
			Message:  "This transaction will send your ENTIRE balance of this asset to another address.",
		})
	}

	if !txn.AssetSender.IsZero() && txn.AssetSender != txn.Sender {
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
		}
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
