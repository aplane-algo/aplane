// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import "fmt"

// FormatAmountWithDecimals formats an amount with the specified number of decimal places.
// If decimals is 0, returns the raw integer value.
func FormatAmountWithDecimals(amountUnits uint64, decimals uint64) string {
	if decimals == 0 {
		return fmt.Sprintf("%d", amountUnits)
	}
	divisor := float64(1)
	for i := uint64(0); i < decimals; i++ {
		divisor *= 10
	}
	return fmt.Sprintf("%.*f", decimals, float64(amountUnits)/divisor)
}
