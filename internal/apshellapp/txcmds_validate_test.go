// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Validate fails as a whole only when every item failed, and returns its
// result, each item with its error, beside that failure; a set in which some
// passed is its result alone.
func TestValidateFailsOnlyWhenEveryItemFailed(t *testing.T) {
	f := newArgsFixture(t) // the signer refuses every account
	result, err := f.app.Validate(context.Background(), ValidateRequest{Account: "nat"})
	if err == nil || err.Error() != "all 1 validation(s) failed" {
		t.Fatalf("Validate() error = %v, want all 1 failed", err)
	}
	if result == nil || result.FailureCount != 1 || len(result.Items) != 1 || result.Items[0].Error == "" {
		t.Fatalf("Validate() result = %+v, want the failed item", result)
	}

	f = newArgsFixture(t)
	f.signsFor = map[string]bool{argsNative: true}
	f.confirms = true
	foreign := types.Address{60}.String() // the signer holds no key for it
	f.eng.SetCache.Sets = map[string][]string{"pair": {argsNative, foreign}}
	result, err = f.app.Validate(context.Background(), ValidateRequest{Account: "@pair"})
	if err != nil {
		t.Fatalf("Validate(@pair) error = %v, want the result alone", err)
	}
	if result.SuccessCount != 1 || result.FailureCount != 1 {
		t.Fatalf("Validate(@pair) = %+v, want one passed and one failed", result)
	}
}

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
