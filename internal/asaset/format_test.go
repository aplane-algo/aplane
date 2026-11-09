// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package asaset

import "testing"

func TestFormatUnits(t *testing.T) {
	for _, tc := range []struct {
		amount, decimals uint64
		want             string
	}{
		{0, 0, "0"}, {5, 0, "5"}, {5, 2, "0.05"}, {150, 2, "1.5"}, {1000000, 6, "1"},
		{18446744073709551615, 19, "1.8446744073709551615"},
	} {
		if got := FormatUnits(tc.amount, tc.decimals); got != tc.want {
			t.Errorf("FormatUnits(%d, %d) = %q, want %q", tc.amount, tc.decimals, got, tc.want)
		}
	}
}

func TestFormatFixed(t *testing.T) {
	for _, tc := range []struct {
		amount, decimals uint64
		want             string
	}{
		{5, 0, "5"}, {5, 2, "0.05"}, {1000, 6, "0.001000"}, {1500000, 6, "1.500000"}, {0, 3, "0.000"},
	} {
		if got := FormatFixed(tc.amount, tc.decimals); got != tc.want {
			t.Errorf("FormatFixed(%d, %d) = %q, want %q", tc.amount, tc.decimals, got, tc.want)
		}
	}
}

func TestDisplay(t *testing.T) {
	if got := (Asset{UnitName: "X\x1bY", Decimals: 2}).Display(150); got != "1.5 X?Y (150 base units)" {
		t.Fatalf("Display() = %q", got)
	}
	if got := (Asset{Decimals: 0}).Display(7); got != "7 (7 base units)" {
		t.Fatalf("Display() without a unit name = %q", got)
	}
}

func TestPrintableReplacesControlAndFormatCharacters(t *testing.T) {
	for in, want := range map[string]string{
		"USDC":            "USDC",
		"Ünï ☃":           "Ünï ☃",
		"A\x1b[2JB":       "A?[2JB",
		"A\nB\rC":         "A?B?C",
		"CDSU\u202e":      "CDSU?",
		"zero\u200bwidth": "zero?width",
		"bad\xff":         "bad�",
	} {
		if got := Printable(in); got != want {
			t.Errorf("Printable(%q) = %q, want %q", in, got, want)
		}
	}
}
