// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func splitAddressListValue(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
}

func resolveAddressListValue(value string) (string, error) {
	entries := splitAddressListValue(value)
	for i, entry := range entries {
		address, err := types.DecodeAddress(strings.ToUpper(entry))
		if err != nil {
			return "", fmt.Errorf("invalid address %q: enter a full account address", entry)
		}
		entries[i] = address.String()
	}
	slices.Sort(entries)
	return strings.Join(slices.Compact(entries), ","), nil
}
