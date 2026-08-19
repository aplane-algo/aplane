// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package identity

import "github.com/aplane-algo/aplane/internal/signerapp/unlockconfig"

// UnlockConfig holds product-store passphrase helper configuration.
// Stored at identities/default/unlock.yaml.
type UnlockConfig = unlockconfig.UnlockConfig

// LoadUnlockConfig reads the product-store unlock config.
// Returns an empty config (not an error) if the file does not exist.
func LoadUnlockConfig(dataRoot string) (*UnlockConfig, error) {
	return unlockconfig.LoadUnlockConfig(dataRoot)
}

// SaveUnlockConfig writes the product-store unlock config atomically.
func SaveUnlockConfig(dataRoot string, cfg *UnlockConfig) error {
	return unlockconfig.SaveUnlockConfig(dataRoot, cfg)
}
