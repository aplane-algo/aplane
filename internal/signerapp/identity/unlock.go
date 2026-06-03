// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package identity

import "github.com/aplane-algo/aplane/internal/signerapp/unlockconfig"

// UnlockConfig holds per-identity passphrase helper configuration.
// Stored at identities/<identity>/unlock.yaml.
type UnlockConfig = unlockconfig.UnlockConfig

// UnlockConfigPath returns the path to an identity's unlock config file.
func UnlockConfigPath(dataRoot, identityID string) string {
	return unlockconfig.UnlockConfigPath(dataRoot, identityID)
}

// LoadUnlockConfig reads the per-identity unlock config.
// Returns an empty config (not an error) if the file does not exist.
func LoadUnlockConfig(dataRoot, identityID string) (*UnlockConfig, error) {
	return unlockconfig.LoadUnlockConfig(dataRoot, identityID)
}

// SaveUnlockConfig writes the per-identity unlock config atomically.
func SaveUnlockConfig(dataRoot, identityID string, cfg *UnlockConfig) error {
	return unlockconfig.SaveUnlockConfig(dataRoot, identityID, cfg)
}

// ClearUnlockConfig removes the per-identity unlock config file.
func ClearUnlockConfig(dataRoot, identityID string) error {
	return unlockconfig.ClearUnlockConfig(dataRoot, identityID)
}
