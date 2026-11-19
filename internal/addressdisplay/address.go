// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package addressdisplay

import (
	"fmt"
)

// AliasLookup provides reverse alias lookup for display.
type AliasLookup interface {
	GetAliasForAddress(address string) string
}

// SignerLookup provides signer key availability for display.
type SignerLookup interface {
	HasAddress(address string) bool
	GetKeyType(address string) string
	// IsRotating reports a rotating account the signer holds. Its current
	// stage authorizes it, a program the signer derives and never lists, so
	// it is signable whatever the chain shows as its auth address.
	IsRotating(address string) bool
}

// AuthLookup provides cached authorization addresses for rekey-aware display.
type AuthLookup interface {
	GetAuthAddress(address string) (string, bool)
}

// FormatAddress formats an address with optional alias display.
func FormatAddress(address string, aliases AliasLookup, signer SignerLookup, auth AuthLookup, colorFormatter ColorFormatter) string {
	effectiveSigningAddress := address

	// A rotating account keeps its own key type: its stage address is in no
	// cache.
	if (signer == nil || !signer.IsRotating(address)) && auth != nil {
		if cachedAuthAddr, exists := auth.GetAuthAddress(address); exists && cachedAuthAddr != "" {
			effectiveSigningAddress = cachedAuthAddr
		}
	}

	formatted := address
	if aliases != nil {
		if alias := aliases.GetAliasForAddress(address); alias != "" {
			formatted = fmt.Sprintf("%s (%s)", address, alias)
		}
	}

	if isAccountSignable(address, signer, auth) {
		keyType := signer.GetKeyType(effectiveSigningAddress)
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

// isAccountSignable is cache.IsAccountSignable's rule over the lookups: a
// rotating account the signer holds, or an account whose auth address (or,
// when not rekeyed, whose own address) the signer holds.
func isAccountSignable(address string, signer SignerLookup, auth AuthLookup) bool {
	if signer == nil {
		return false
	}
	if signer.IsRotating(address) {
		return true
	}

	if auth != nil {
		authAddr, hasRekey := auth.GetAuthAddress(address)
		if hasRekey && authAddr != "" {
			return signer.HasAddress(authAddr)
		}
	}

	return signer.HasAddress(address)
}
