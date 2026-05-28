// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cmdspec

import (
	"fmt"
	"strings"
)

// AssetRef is a parse-time semantic asset reference such as "algo", "usdc", or "31566704".
type AssetRef string

func ParseAssetRef(raw string) (AssetRef, error) {
	ref := strings.TrimSpace(raw)
	if ref == "" {
		return "", fmt.Errorf("empty asset reference")
	}
	return AssetRef(ref), nil
}

func (a AssetRef) String() string {
	return string(a)
}

// AmountText is a parse-time human-facing amount such as "1" or "1.25".
type AmountText string

func ParseAmountText(raw string) (AmountText, error) {
	amount := strings.TrimSpace(raw)
	if amount == "" {
		return "", fmt.Errorf("empty amount")
	}
	return AmountText(amount), nil
}

func (a AmountText) String() string {
	return string(a)
}
