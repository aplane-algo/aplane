// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import "testing"

func TestDecorateValidateResultAddsSummaryForMultipleItems(t *testing.T) {
	result := &ValidateCommandResult{
		Items: []ValidateItemResult{
			{Address: "A"},
			{Address: "B"},
		},
		SuccessCount: 1,
		FailureCount: 1,
	}

	decorateValidateResult(result)

	if len(result.SummaryLines) != 3 {
		t.Fatalf("len(SummaryLines) = %d, want 3", len(result.SummaryLines))
	}
	if got, want := result.SummaryLines[1], "Successful: 1/2"; got != want {
		t.Fatalf("SummaryLines[1] = %q, want %q", got, want)
	}
}

func TestDecorateValidateResultSkipsSummaryForSingleItem(t *testing.T) {
	result := &ValidateCommandResult{
		Items: []ValidateItemResult{{Address: "A"}},
	}

	decorateValidateResult(result)

	if len(result.SummaryLines) != 0 {
		t.Fatalf("len(SummaryLines) = %d, want 0", len(result.SummaryLines))
	}
}
