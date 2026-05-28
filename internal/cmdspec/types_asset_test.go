// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cmdspec

import "testing"

func TestParseAssetRef(t *testing.T) {
	ref, err := ParseAssetRef(" usdc ")
	if err != nil {
		t.Fatalf("ParseAssetRef() error = %v", err)
	}
	if ref.String() != "usdc" {
		t.Fatalf("ParseAssetRef() = %q, want usdc", ref)
	}
}

func TestParseAssetRefEmpty(t *testing.T) {
	if _, err := ParseAssetRef(" "); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseAmountText(t *testing.T) {
	amount, err := ParseAmountText(" 1.25 ")
	if err != nil {
		t.Fatalf("ParseAmountText() error = %v", err)
	}
	if amount.String() != "1.25" {
		t.Fatalf("ParseAmountText() = %q, want 1.25", amount)
	}
}

func TestParseAmountTextEmpty(t *testing.T) {
	if _, err := ParseAmountText(" "); err == nil {
		t.Fatal("expected error")
	}
}
