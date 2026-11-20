// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package unlockconfig owns product-store auto-unlock configuration.
package unlockconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"gopkg.in/yaml.v3"
)

// Auto-unlock methods, as Method reports them.
const (
	MethodNone         = "none"
	MethodPassfile     = "passfile"
	MethodSystemdCreds = "systemd-creds"
	MethodCustom       = "custom"
)

// ErrMalformed reports an unlock.yaml that was read but does not parse.
var ErrMalformed = errors.New("malformed unlock config")

// UnlockConfig holds product-store passphrase helper configuration.
// Stored at identities/default/unlock.yaml.
type UnlockConfig struct {
	PassphraseCommandArgv []string          `yaml:"passphrase_command_argv,omitempty"`
	PassphraseCommandEnv  map[string]string `yaml:"passphrase_command_env,omitempty"`
}

// UnlockConfigPath returns the fixed product unlock config path.
func UnlockConfigPath(dataRoot string) string {
	return filepath.Join(storepaths.NewPaths(dataRoot).ProductDir(), "unlock.yaml")
}

// LoadUnlockConfig reads the product-store unlock config.
// Returns an empty config (not an error) if the file does not exist.
func LoadUnlockConfig(dataRoot string) (*UnlockConfig, error) {
	path := UnlockConfigPath(dataRoot)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &UnlockConfig{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read unlock config: %w", err)
	}

	var cfg UnlockConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return &cfg, nil
}

// SaveUnlockConfig writes the product-store unlock config atomically.
func SaveUnlockConfig(dataRoot string, cfg *UnlockConfig) error {
	return saveUnlockConfig(dataRoot, cfg, nil)
}

// SaveUnlockConfigForService writes a private unlock configuration owned by
// the resolved signer service account. It is used by root-run appass without
// any post-publication pathname chown or chmod.
func SaveUnlockConfigForService(dataRoot string, cfg *UnlockConfig, uid, gid int) error {
	owner := [2]int{uid, gid}
	return saveUnlockConfig(dataRoot, cfg, &owner)
}

func saveUnlockConfig(dataRoot string, cfg *UnlockConfig, owner *[2]int) error {
	path := UnlockConfigPath(dataRoot)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal unlock config: %w", err)
	}

	var writeErr error
	if owner == nil {
		writeErr = fsutil.WriteFileDurable(path, data)
	} else {
		writeErr = fsutil.WriteServiceOwnedFileDurable(path, data, owner[0], owner[1])
	}
	if writeErr != nil {
		return fmt.Errorf("failed to write unlock config: %w", writeErr)
	}
	return nil
}

// ClearUnlockConfig removes the product-store unlock config file.
func ClearUnlockConfig(dataRoot string) error {
	path := UnlockConfigPath(dataRoot)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove unlock config: %w", err)
	}
	return nil
}

// HasPassphraseCommand returns true if this unlock config has a passphrase command configured.
func (c *UnlockConfig) HasPassphraseCommand() bool {
	return len(c.PassphraseCommandArgv) > 0
}

// Method names the auto-unlock method a helper argv selects: "none" without a
// helper, "passfile" or "systemd-creds" for the bundled helpers, else "custom".
func (c *UnlockConfig) Method() string {
	if c == nil || len(c.PassphraseCommandArgv) == 0 {
		return MethodNone
	}
	bin := c.PassphraseCommandArgv[0]
	switch {
	case strings.HasSuffix(bin, "/appass-file") || bin == "appass-file":
		return MethodPassfile
	case strings.HasSuffix(bin, "/appass-systemd-creds") || bin == "appass-systemd-creds":
		return MethodSystemdCreds
	default:
		return MethodCustom
	}
}
