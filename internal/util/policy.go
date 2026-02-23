// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package util provides policy checking for transaction signing.
//
// # Two-Layer Approval Model
//
// Transactions must pass two layers before being signed:
//
//  1. Policy Linting: Hard constraints that MUST be satisfied. If a transaction
//     fails policy linting, it is rejected with no human override possible.
//
//  2. Human Approval: Determines if operator intervention is needed. Includes
//     warnings about dangerous fields (which humans CAN override) and auto-approve
//     rules that bypass human intervention.
//
// For groups, only group-level human approval applies (no per-transaction approval).
// For single transactions, transaction-level human approval applies.
package util

import (
	"encoding/hex"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// Default policy thresholds
const (
	DefaultMaxFeeMicroAlgos = 1_000_000 // 1 ALGO
)

// ============================================================================
// LAYER 1: POLICY LINTING (hard rejection, no human override)
// ============================================================================

// CheckGroupPolicyLinter validates a group of transactions against policy constraints.
// Returns an error if any constraint is violated - the entire group is rejected.
// This is called BEFORE human approval and cannot be overridden.
func CheckGroupPolicyLinter(txns []types.Transaction) error {
	// TODO: Add group-level policy checks, e.g.:
	// - Maximum group size
	// - Mixed sender restrictions
	// - Group-level spending limits
	return nil
}

// CheckTxnPolicyLinter validates a single transaction against policy constraints.
// Returns an error if any constraint is violated - the transaction is rejected.
// This is called BEFORE human approval and cannot be overridden.
func CheckTxnPolicyLinter(txn types.Transaction, sender string) error {
	// TODO: Add transaction-level policy checks, e.g.:
	// - Sender doesn't overspend (requires balance info)
	// - Transaction amount within configured limits
	// - Recipient not on blocklist
	return nil
}

// ============================================================================
// LAYER 2: HUMAN APPROVAL
// ============================================================================

// --- 2a: Warnings (displayed to operator, can be overridden) ---

// CheckTxnWarnings analyzes a transaction for dangerous fields that should be
// shown to the operator. These are warnings only - the operator can still approve.
// Returns a list of policy violations for display in the TUI.
func CheckTxnWarnings(txnBytesHex string) []protocol.PolicyViolation {
	if txnBytesHex == "" {
		return nil
	}

	txn, err := DecodeTxnFromHex(txnBytesHex)
	if err != nil {
		return nil
	}

	return checkTxnWarningsInternal(txn)
}

// checkTxnWarningsInternal checks a decoded transaction for warning-level issues.
func checkTxnWarningsInternal(txn types.Transaction) []protocol.PolicyViolation {
	var violations []protocol.PolicyViolation

	// Check for RekeyTo - transfers signing authority
	if !txn.RekeyTo.IsZero() {
		violations = append(violations, protocol.PolicyViolation{
			Field:    "RekeyTo",
			Value:    txn.RekeyTo.String(),
			Severity: "critical",
			Message:  "This transaction will PERMANENTLY transfer signing authority to another address. You will lose control of this account.",
		})
	}

	// Check for CloseRemainderTo - closes account and sends all remaining balance
	if !txn.CloseRemainderTo.IsZero() {
		violations = append(violations, protocol.PolicyViolation{
			Field:    "CloseRemainderTo",
			Value:    txn.CloseRemainderTo.String(),
			Severity: "critical",
			Message:  "This transaction will close your account and send ALL remaining ALGO to another address.",
		})
	}

	// Check for AssetCloseTo - closes out entire ASA balance
	if !txn.AssetCloseTo.IsZero() {
		violations = append(violations, protocol.PolicyViolation{
			Field:    "AssetCloseTo",
			Value:    txn.AssetCloseTo.String(),
			Severity: "warning",
			Message:  "This transaction will send your ENTIRE balance of this asset to another address.",
		})
	}

	// Check for AssetSender (Clawback)
	if !txn.AssetSender.IsZero() && txn.AssetSender != txn.Sender {
		violations = append(violations, protocol.PolicyViolation{
			Field:    "AssetSender",
			Value:    txn.AssetSender.String(),
			Severity: "warning",
			Message:  "CLAWBACK: This transaction will move funds from another account using your clawback authority.",
		})
	}

	// Check for excessive fees
	if uint64(txn.Fee) > DefaultMaxFeeMicroAlgos {
		algoFee := float64(txn.Fee) / 1_000_000
		violations = append(violations, protocol.PolicyViolation{
			Field:    "Fee",
			Value:    fmt.Sprintf("%.6f ALGO", algoFee),
			Severity: "warning",
			Message:  fmt.Sprintf("Transaction fee is unusually high (%.6f ALGO). Normal fees are ~0.001 ALGO.", algoFee),
		})
	}

	return violations
}

// ============================================================================
// HELPERS
// ============================================================================

// DecodeTxnFromHex decodes a transaction from hex-encoded bytes.
// Handles both raw msgpack and "TX" prefixed formats.
func DecodeTxnFromHex(txnBytesHex string) (types.Transaction, error) {
	var txn types.Transaction

	if txnBytesHex == "" {
		return txn, fmt.Errorf("empty transaction bytes")
	}

	txnBytes, err := hex.DecodeString(txnBytesHex)
	if err != nil {
		return txn, fmt.Errorf("failed to decode hex: %w", err)
	}

	// Skip "TX" prefix if present
	if len(txnBytes) > 2 && txnBytes[0] == 'T' && txnBytes[1] == 'X' {
		txnBytes = txnBytes[2:]
	}

	if err := msgpack.Decode(txnBytes, &txn); err != nil {
		return txn, fmt.Errorf("failed to decode msgpack: %w", err)
	}

	return txn, nil
}
