// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package asaset

import (
	"fmt"
	"strings"
	"unicode"
)

// Amounts of an asset are shown the same way wherever the signer shows them:
// policy reviews, limit messages and approval prompts. A known asset is shown
// in its display units with the base units beside them; an asset whose
// decimals are unknown is shown in base units only, with no decimal count
// guessed.

// FormatFixed formats a base-unit amount with exactly decimals places:
// 1500000 with 6 decimals is "1.500000".
func FormatFixed(amount, decimals uint64) string {
	digits := fmt.Sprintf("%d", amount)
	places := int(decimals)
	if places == 0 {
		return digits
	}
	if len(digits) <= places {
		digits = strings.Repeat("0", places-len(digits)+1) + digits
	}
	return digits[:len(digits)-places] + "." + digits[len(digits)-places:]
}

// FormatUnits formats a base-unit amount with decimals places, without
// trailing zeros: 1500000 with 6 decimals is "1.5".
func FormatUnits(amount, decimals uint64) string {
	fixed := FormatFixed(amount, decimals)
	if !strings.Contains(fixed, ".") {
		return fixed
	}
	return strings.TrimSuffix(strings.TrimRight(fixed, "0"), ".")
}

// Printable is an issuer-chosen name with control characters replaced, so
// it cannot drive the terminal it is shown on.
func Printable(name string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, name)
}

// Display is raw base units of a in its display units with the base units
// beside them: "1.5 XYZ (150 base units)".
func (a Asset) Display(raw uint64) string {
	display := FormatUnits(raw, a.Decimals)
	if unit := Printable(a.UnitName); unit != "" {
		display += " " + unit
	}
	return fmt.Sprintf("%s (%d base units)", display, raw)
}
