// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package addressderive

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Ed25519Deriver derives Algorand addresses from Ed25519 public keys.
type Ed25519Deriver struct{}

// DeriveAddress derives an Algorand address from an Ed25519 public key.
func (d *Ed25519Deriver) DeriveAddress(publicKeyHex string, params map[string]string) (string, error) {
	_ = params
	pubBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return "", fmt.Errorf("ed25519 public key length %d invalid (expected %d bytes)", len(pubBytes), ed25519.PublicKeySize)
	}

	var address types.Address
	copy(address[:], pubBytes)
	return address.String(), nil
}

// GetEd25519 returns the Ed25519 address deriver.
func GetEd25519() *Ed25519Deriver {
	return &Ed25519Deriver{}
}
