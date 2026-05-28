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
}

// AuthLookup provides cached authorization addresses for rekey-aware display.
type AuthLookup interface {
	GetAuthAddress(address string) (string, bool)
}

// FormatAddress formats an address with optional alias display.
func FormatAddress(address string, aliases AliasLookup, signer SignerLookup, auth AuthLookup, authAddress string, colorFormatter ColorFormatter) string {
	effectiveSigningAddress := address

	if authAddress != "" && authAddress != address {
		effectiveSigningAddress = authAddress
	} else if auth != nil {
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
		if colorFormatter != nil {
			return FormatWithKeyColor(formatted, keyType, colorFormatter)
		}
		if !SupportsColor() {
			return formatted + " @"
		}
	}

	return formatted
}

func isAccountSignable(address string, signer SignerLookup, auth AuthLookup) bool {
	if signer == nil {
		return false
	}

	if auth != nil {
		authAddr, hasRekey := auth.GetAuthAddress(address)
		if hasRekey && authAddr != "" {
			return signer.HasAddress(authAddr)
		}
	}

	return signer.HasAddress(address)
}
