// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package keys

import (
	"encoding/hex"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Ed25519AddressDeriver implements AddressDeriver for Ed25519
type Ed25519AddressDeriver struct{}

// DeriveAddress derives an Algorand address from an Ed25519 public key
func (d *Ed25519AddressDeriver) DeriveAddress(publicKeyHex string, params map[string]string) (string, error) {
	_ = params
	pubBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	var address types.Address
	copy(address[:], pubBytes)
	return address.String(), nil
}

// GetEd25519AddressDeriver returns the Ed25519 address deriver
func GetEd25519AddressDeriver() *Ed25519AddressDeriver {
	return &Ed25519AddressDeriver{}
}
