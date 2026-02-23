// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package aplane

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Default ports matching apsignerd defaults.
const (
	DefaultSignerPort = 11270
	DefaultSSHPort    = 1127
	DefaultDataDir    = "~/.aplane"
	DefaultTimeout    = 90 // seconds
)

// ExpandPath expands ~ to the user's home directory.
func ExpandPath(path string) string {
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[1:])
	}
	return path
}

// LoadConfig loads client configuration from dataDir/config.yaml.
func LoadConfig(dataDir string) (*Config, error) {
	config := &Config{
		SignerPort: DefaultSignerPort,
	}

	configPath := filepath.Join(dataDir, "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return config, nil // Return defaults if no config file
		}
		return nil, err
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return config, nil // Return defaults on parse error
	}

	return config, nil
}

// LoadToken loads the authentication token from the given path.
func LoadToken(tokenPath string) (string, error) {
	path := ExpandPath(tokenPath)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrTokenNotFound
		}
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// LoadTokenFromDir loads the token from dataDir/aplane.token.
func LoadTokenFromDir(dataDir string) (string, error) {
	tokenPath := filepath.Join(dataDir, "aplane.token")
	return LoadToken(tokenPath)
}

// ResolveDataDir returns the data directory from: parameter > env var > default.
func ResolveDataDir(dataDir string) string {
	if dataDir != "" {
		return ExpandPath(dataDir)
	}
	if envDir := os.Getenv("APCLIENT_DATA"); envDir != "" {
		return ExpandPath(envDir)
	}
	return ExpandPath(DefaultDataDir)
}
