// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package addressdisplay

import "fmt"

// AliasLookup provides reverse alias lookup for display.
type AliasLookup interface {
	GetAliasForAddress(address string) string
}

// FormatAddress formats an address with optional alias display. When signable
// is true, the address is coloured by keyType, or marked " @" where no colour
// is applied.
func FormatAddress(address string, aliases AliasLookup, keyType string, signable bool, colorFormatter ColorFormatter) string {
	formatted := address
	if aliases != nil {
		if alias := aliases.GetAliasForAddress(address); alias != "" {
			formatted = fmt.Sprintf("%s (%s)", address, alias)
		}
	}

	if signable {
		colored, applied := formatWithKeyColorApplied(formatted, keyType, colorFormatter)
		if applied {
			return colored
		}
		// Signability is normally conveyed by color; whenever color was not
		// emitted (no formatter, non-color terminal, unregistered key type),
		// fall back to the plain-text marker.
		return formatted + " @"
	}

	return formatted
}
