// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"math"
	"testing"
)

func TestFormatAmountWithDecimals(t *testing.T) {
	tests := []struct {
		name        string
		amountUnits uint64
		decimals    uint64
		expected    string
	}{
		{
			name:        "zero decimals",
			amountUnits: 100,
			decimals:    0,
			expected:    "100",
		},
		{
			name:        "zero amount zero decimals",
			amountUnits: 0,
			decimals:    0,
			expected:    "0",
		},
		{
			name:        "6 decimals - 1 unit",
			amountUnits: 1000000,
			decimals:    6,
			expected:    "1.000000",
		},
		{
			name:        "6 decimals - fractional",
			amountUnits: 1500000,
			decimals:    6,
			expected:    "1.500000",
		},
		{
			name:        "6 decimals - small",
			amountUnits: 1,
			decimals:    6,
			expected:    "0.000001",
		},
		{
			name:        "8 decimals",
			amountUnits: 100000000,
			decimals:    8,
			expected:    "1.00000000",
		},
		{
			name:        "8 decimals - fractional",
			amountUnits: 123456789,
			decimals:    8,
			expected:    "1.23456789",
		},
		{
			name:        "2 decimals",
			amountUnits: 150,
			decimals:    2,
			expected:    "1.50",
		},
		{
			name:        "18 decimals - large precision",
			amountUnits: 1000000000000000000,
			decimals:    18,
			expected:    "1.000000000000000000",
		},
		{
			name:        "zero amount with decimals",
			amountUnits: 0,
			decimals:    6,
			expected:    "0.000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatAmountWithDecimals(tt.amountUnits, tt.decimals)
			if got != tt.expected {
				t.Errorf("FormatAmountWithDecimals(%d, %d) = %q, want %q",
					tt.amountUnits, tt.decimals, got, tt.expected)
			}
		})
	}
}

// TestFormatAmountWithDecimalsEdgeCases tests edge cases
func TestFormatAmountWithDecimalsEdgeCases(t *testing.T) {
	// Test very high decimals doesn't panic
	got := FormatAmountWithDecimals(1, 30)
	if got == "" {
		t.Error("FormatAmountWithDecimals with high decimals returned empty string")
	}

	// Test max uint64 with 0 decimals
	got = FormatAmountWithDecimals(math.MaxUint64, 0)
	if got == "" {
		t.Error("FormatAmountWithDecimals with MaxUint64 returned empty string")
	}
}
