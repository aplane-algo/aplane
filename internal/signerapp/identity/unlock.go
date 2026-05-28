// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package identity

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// UnlockConfig holds per-identity passphrase helper configuration.
// Stored at identities/<identity>/unlock.yaml.
type UnlockConfig struct {
	PassphraseCommandArgv []string          `yaml:"passphrase_command_argv,omitempty"`
	PassphraseCommandEnv  map[string]string `yaml:"passphrase_command_env,omitempty"`
}

// UnlockConfigPath returns the path to an identity's unlock config file.
func UnlockConfigPath(dataRoot, identityID string) string {
	return filepath.Join(dataRoot, "identities", identityID, "unlock.yaml")
}

// LoadUnlockConfig reads the per-identity unlock config.
// Returns an empty config (not an error) if the file does not exist.
func LoadUnlockConfig(dataRoot, identityID string) (*UnlockConfig, error) {
	path := UnlockConfigPath(dataRoot, identityID)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &UnlockConfig{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read unlock config: %w", err)
	}

	var cfg UnlockConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse unlock config: %w", err)
	}
	return &cfg, nil
}

// SaveUnlockConfig writes the per-identity unlock config atomically.
func SaveUnlockConfig(dataRoot, identityID string, cfg *UnlockConfig) error {
	path := UnlockConfigPath(dataRoot, identityID)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal unlock config: %w", err)
	}

	// Atomic write via temp file
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("failed to write unlock config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("failed to rename unlock config: %w", err)
	}
	return nil
}

// ClearUnlockConfig removes the per-identity unlock config file.
func ClearUnlockConfig(dataRoot, identityID string) error {
	path := UnlockConfigPath(dataRoot, identityID)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove unlock config: %w", err)
	}
	return nil
}

// HasPassphraseCommand returns true if this unlock config has a passphrase command configured.
func (c *UnlockConfig) HasPassphraseCommand() bool {
	return len(c.PassphraseCommandArgv) > 0
}
