// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package approvalpolicy provides warning-level checks for signer approval
// flows. These warnings are displayed to operators and may be overridden.
package approvalpolicy

import (
	"github.com/algorand/go-algorand-sdk/v2/types"

	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/txnreview"
)

// Context is what a warning check knows about the signer's own position. The
// rules themselves live in internal/txnreview, where apshell's review of a
// plugin-built group uses them too.
type Context = txnreview.FindingContext

// CheckDecodedTxnWarningsIn analyzes a decoded transaction for warning-level
// issues.
func CheckDecodedTxnWarningsIn(txn types.Transaction, ctx Context) []signerapproval.Violation {
	findings := txnreview.Findings(txn, ctx)
	if len(findings) == 0 {
		return nil
	}
	violations := make([]signerapproval.Violation, len(findings))
	for i, finding := range findings {
		violations[i] = Violation(finding)
	}
	return violations
}

// Violation is a finding as a prompt's warning.
func Violation(finding txnreview.Finding) signerapproval.Violation {
	return signerapproval.Violation{
		Field: finding.Field, Value: finding.Value, Severity: signerapproval.ViolationSeverity(finding.Level()), Message: finding.Message,
	}
}
