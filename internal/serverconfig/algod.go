// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package serverconfig

import (
	"fmt"

	apconfig "github.com/aplane-algo/aplane/internal/config"
)

// ServerNetworkConfig holds grouped apsigner settings for a single network context token.
type ServerNetworkConfig struct {
	Algod       *apconfig.AlgodNetworkConfig   `yaml:"algod" description:"Algod settings for this network context token"`
	Indexer     *apconfig.IndexerNetworkConfig `yaml:"indexer,omitempty" description:"Optional Indexer for this network context token; the stage table worker reads a rotating account's last rekey from it to find the stage to try first"`
	GenesisHash string                         `yaml:"genesis_hash,omitempty" description:"Custom signer policy genesis hash for this network context token" default:""`
}

// ServerNetworkConfigs is a map of network context token → grouped apsigner settings.
type ServerNetworkConfigs map[string]*ServerNetworkConfig

func mergeServerNetworkAlgodConfig(legacy apconfig.AlgodConfig, networks ServerNetworkConfigs) (apconfig.AlgodConfig, error) {
	out := legacy
	if out == nil && len(networks) > 0 {
		out = make(apconfig.AlgodConfig, len(networks))
	}

	for network, cfg := range networks {
		if err := apconfig.ValidateNetworkID(network); err != nil {
			return nil, err
		}
		if cfg == nil || cfg.Algod == nil {
			continue
		}
		out[network] = cfg.Algod
	}

	return out, nil
}

// mergeServerNetworkIndexerConfig indexes the networks that name an Indexer
// server. A server that is not an http or https URL with a host is an error
// naming the network; the URL itself is not repeated, since an operator may
// have put a credential in it.
func mergeServerNetworkIndexerConfig(networks ServerNetworkConfigs) (map[string]*apconfig.IndexerNetworkConfig, error) {
	var out map[string]*apconfig.IndexerNetworkConfig
	for network, cfg := range networks {
		if err := apconfig.ValidateNetworkID(network); err != nil {
			return nil, err
		}
		if cfg == nil || cfg.Indexer == nil || cfg.Indexer.Server == "" {
			continue
		}
		if err := apconfig.ValidateIndexerServer(cfg.Indexer.Server); err != nil {
			return nil, fmt.Errorf("networks.%s.indexer.server is %w", network, err)
		}
		if out == nil {
			out = make(map[string]*apconfig.IndexerNetworkConfig)
		}
		out[network] = cfg.Indexer
	}
	return out, nil
}

func mergeServerNetworkGenesisHashConfig(legacy map[string]string, networks ServerNetworkConfigs) (map[string]string, error) {
	out := legacy
	if out == nil && len(networks) > 0 {
		out = make(map[string]string)
	}

	for network, cfg := range networks {
		if err := apconfig.ValidateNetworkID(network); err != nil {
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
