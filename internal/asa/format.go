// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package asa

import (
	"github.com/aplane-algo/aplane/internal/asaset"
)

// FormatAmountWithDecimals formats an amount with the specified number of
// decimal places. If decimals is 0, it returns the raw integer value.
func FormatAmountWithDecimals(amountUnits uint64, decimals uint64) string {
	return asaset.FormatFixed(amountUnits, decimals)
}
