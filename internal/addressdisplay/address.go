// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package addressdisplay

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/cache"
)

// AliasLookup provides reverse alias lookup for display.
type AliasLookup interface {
	GetAliasForAddress(address string) string
}

// FormatAddress formats an address with optional alias display. An account
// apshell calls signable (cache.IsAccountSignable) is coloured by the key
// type of the key that signs for it, or marked " @" where there is no colour.
func FormatAddress(address string, aliases AliasLookup, signer *cache.SignerCache, auth *cache.AuthAddressCache, colorFormatter ColorFormatter) string {
	formatted := address
	if aliases != nil {
		if alias := aliases.GetAliasForAddress(address); alias != "" {
			formatted = fmt.Sprintf("%s (%s)", address, alias)
		}
	}

	if cache.IsAccountSignable(address, signer, auth) {
		keyType := signer.GetKeyType(cache.SigningAddress(address, signer, auth))
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
