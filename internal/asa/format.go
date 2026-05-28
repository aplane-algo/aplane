// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package asa

import (
	"fmt"
	"strings"
)

// FormatAmountWithDecimals formats an amount with the specified number of
// decimal places. If decimals is 0, it returns the raw integer value.
func FormatAmountWithDecimals(amountUnits uint64, decimals uint64) string {
	if decimals == 0 {
		return fmt.Sprintf("%d", amountUnits)
	}
	digits := fmt.Sprintf("%d", amountUnits)
	if uint64(len(digits)) <= decimals {
		return "0." + strings.Repeat("0", int(decimals)-len(digits)) + digits
	}
	intPart := digits[:len(digits)-int(decimals)]
	fracPart := digits[len(digits)-int(decimals):]
	return intPart + "." + fracPart
}
