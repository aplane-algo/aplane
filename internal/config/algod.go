// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import "fmt"

// AlgodNetworkConfig holds algod settings for a single network.
type AlgodNetworkConfig struct {
	Server string `yaml:"server" description:"Algod server URL" default:""`
	Token  string `yaml:"token" description:"Algod API token" default:""`
}

// AlgodConfig is a map of network name → settings.
type AlgodConfig map[string]*AlgodNetworkConfig

// ClientNetworkConfig holds grouped apshell settings for a single network context token.
type ClientNetworkConfig struct {
	Algod *AlgodNetworkConfig `yaml:"algod" description:"Algod settings for this network context token"`
}

// ClientNetworkConfigs is a map of network context token → grouped apshell settings.
type ClientNetworkConfigs map[string]*ClientNetworkConfig

// ServerNetworkConfig holds grouped apsigner settings for a single network context token.
type ServerNetworkConfig struct {
	Algod       *AlgodNetworkConfig `yaml:"algod" description:"Algod settings for this network context token"`
	GenesisHash string              `yaml:"genesis_hash,omitempty" description:"Custom signer policy genesis hash for this network context token" default:""`
}

// ServerNetworkConfigs is a map of network context token → grouped apsigner settings.
type ServerNetworkConfigs map[string]*ServerNetworkConfig

// GetNetwork returns the algod config for the given network, or an error if not configured.
func (a AlgodConfig) GetNetwork(network string) (*AlgodNetworkConfig, error) {
	if a == nil {
		return nil, fmt.Errorf("algod not configured")
	}
	cfg, ok := a[network]
	if !ok || cfg == nil {
		return nil, fmt.Errorf("algod not configured for network %s", network)
	}
	return cfg, nil
}

func mergeClientNetworkAlgodConfig(legacy AlgodConfig, networks ClientNetworkConfigs) (AlgodConfig, error) {
	out := legacy
	if out == nil && len(networks) > 0 {
		out = make(AlgodConfig, len(networks))
	}

	for network, cfg := range networks {
		if err := ValidateNetworkID(network); err != nil {
			return nil, err
		}
		if cfg == nil || cfg.Algod == nil {
			continue
		}
		out[network] = cfg.Algod
	}

	return out, nil
}

func mergeServerNetworkAlgodConfig(legacy AlgodConfig, networks ServerNetworkConfigs) (AlgodConfig, error) {
	out := legacy
	if out == nil && len(networks) > 0 {
		out = make(AlgodConfig, len(networks))
	}

	for network, cfg := range networks {
		if err := ValidateNetworkID(network); err != nil {
			return nil, err
		}
		if cfg == nil || cfg.Algod == nil {
			continue
		}
		out[network] = cfg.Algod
	}

	return out, nil
}

func mergeServerNetworkGenesisHashConfig(legacy map[string]string, networks ServerNetworkConfigs) (map[string]string, error) {
	out := legacy
	if out == nil && len(networks) > 0 {
		out = make(map[string]string)
	}

	for network, cfg := range networks {
		if err := ValidateNetworkID(network); err != nil {
			return nil, err
		}
		if cfg == nil || cfg.GenesisHash == "" {
			continue
		}
		if out == nil {
			out = make(map[string]string)
		}
		if existing, ok := out[cfg.GenesisHash]; ok && existing != network {
			return nil, fmt.Errorf("genesis hash %q maps to both %q and %q", cfg.GenesisHash, existing, network)
		}
		out[cfg.GenesisHash] = network
	}

	return out, nil
}
