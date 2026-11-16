// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/txnreview"
)

// describeAs is a describer that says text of every transaction: its first
// line is the title, and each indented line after it a field.
func describeAs(text string) DescribeTxnFunc {
	lines := strings.Split(text, "\n  ")
	details := txnreview.Details{Title: lines[0]}
	for _, line := range lines[1:] {
		details.Fields = append(details.Fields, txnreview.Field{Value: line})
	}
	return func(types.Transaction) txnreview.Details { return details }
}
