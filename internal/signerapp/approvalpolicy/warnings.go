// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package approvalpolicy provides warning-level checks for signer approval
// flows. These warnings are displayed to operators and may be overridden.
package approvalpolicy

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/txnreview"
)

// Default policy thresholds.
const (
	DefaultMaxFeeMicroAlgos = txnreview.DefaultMaxFeeMicroAlgos // 1 ALGO
)

// Context is what a warning check knows about the signer's own position. The
// rules themselves live in internal/txnreview, where apshell's review of a
// plugin-built group uses them too.
type Context = txnreview.FindingContext

// CheckGroupWarnings analyzes each transaction in a group for dangerous
// fields. Returns aggregated warnings prefixed with the transaction index.
func CheckGroupWarnings(txns []types.Transaction, knownAddresses map[string]bool) []signerapproval.Violation {
	return CheckGroupWarningsIn(txns, Context{KnownAddresses: knownAddresses}, nil)
}

// CheckGroupWarningsIn is CheckGroupWarnings with a full Context. A rekey-to
// list belongs to one account, so listed gives each position its own, by index,
// in place of ctx.ListedRekeyTargets: another position's rekey to the same
// address is not a listed handover.
func CheckGroupWarningsIn(txns []types.Transaction, ctx Context, listed map[int]map[string]bool) []signerapproval.Violation {
	var all []signerapproval.Violation
	for i, txn := range txns {
		txnCtx := ctx
		txnCtx.ListedRekeyTargets = listed[i]
		for _, v := range CheckDecodedTxnWarningsIn(txn, txnCtx) {
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
	findings := txnreview.Findings(txn, ctx)
	if len(findings) == 0 {
		return nil
	}
	violations := make([]signerapproval.Violation, len(findings))
	for i, finding := range findings {
		severity := signerapproval.ViolationSeverityWarning
		if finding.Critical {
			severity = signerapproval.ViolationSeverityCritical
		}
		violations[i] = signerapproval.Violation{
			Field: finding.Field, Value: finding.Value, Severity: severity, Message: finding.Message,
		}
	}
	return violations
}
