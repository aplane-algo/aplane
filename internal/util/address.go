// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import "fmt"

// FormatAddressShort returns address in abbreviated "ABCD..WXYZ" format.
// For addresses <= 12 characters, returns unchanged.
func FormatAddressShort(addr string) string {
	if len(addr) <= 12 {
		return addr
	}
	return addr[:4] + ".." + addr[len(addr)-4:]
}

// FormatAddressWithAlias returns "ABCD..WXYZ (alias)" if alias exists,
// otherwise just "ABCD..WXYZ".
// If aliasCache is nil, returns shortened address only.
func FormatAddressWithAlias(addr string, aliasCache *AliasCache) string {
	short := FormatAddressShort(addr)
	if aliasCache == nil {
		return short
	}
	if alias := aliasCache.GetAliasForAddress(addr); alias != "" {
		return fmt.Sprintf("%s (%s)", short, alias)
	}
	return short
}
