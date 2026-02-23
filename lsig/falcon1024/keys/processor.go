// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package falconkeys

// FalconAddressDeriver implements AddressDeriver for Falcon-1024
type FalconAddressDeriver struct {
	keyType string // The versioned key type (e.g., "falcon1024-v1")
}

// DeriveAddress derives an Algorand address from a Falcon public key
// using the deriver's key type (which determines the version).
func (d *FalconAddressDeriver) DeriveAddress(publicKeyHex string, params map[string]string) (string, error) {
	return DeriveFalconAddressForType(publicKeyHex, d.keyType, params)
}

// GetFalconAddressDeriverForType returns a Falcon address deriver for the specified key type
func GetFalconAddressDeriverForType(keyType string) *FalconAddressDeriver {
	return &FalconAddressDeriver{keyType: keyType}
}
