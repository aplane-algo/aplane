// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"errors"
	"fmt"
	"net/url"
)

// AlgodNetworkConfig holds algod settings for a single network.
type AlgodNetworkConfig struct {
	Server string `yaml:"server" description:"Algod server URL" default:""`
	Token  string `yaml:"token" description:"Algod API token" default:""`
}

// AlgodConfig is a map of network name → settings.
type AlgodConfig map[string]*AlgodNetworkConfig

// IndexerNetworkConfig holds Indexer settings for a single network. Only the
// signer reads one: it looks up a rotating account's last rekey there to
// find the stage to try first. Empty Server means no Indexer.
type IndexerNetworkConfig struct {
	Server string `yaml:"server" description:"Indexer base URL; empty means no Indexer for this network" default:""`
	Token  string `yaml:"token" description:"Indexer API token" default:""`
}

// ErrIndexerServerNotURL reports an Indexer server that is not an http or
// https URL with a host.
var ErrIndexerServerNotURL = errors.New("not an http or https URL with a host")

// ValidateIndexerServer checks that server can be an Indexer's base URL: an
// http or https URL with a host. It is the rule the signer's configuration
// loader applies, so a setup tool that writes the setting can refuse what
// the signer would. The error does not repeat server, which may hold a
// credential.
func ValidateIndexerServer(server string) error {
	u, err := url.Parse(server)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ErrIndexerServerNotURL
	}
	return nil
}

// ClientNetworkConfig holds grouped apshell settings for a single network context token.
type ClientNetworkConfig struct {
	Algod *AlgodNetworkConfig `yaml:"algod" description:"Algod settings for this network context token"`
}

// ClientNetworkConfigs is a map of network context token → grouped apshell settings.
type ClientNetworkConfigs map[string]*ClientNetworkConfig

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

func mergeClientNetworkAlgodConfig(networks ClientNetworkConfigs) (AlgodConfig, error) {
	var out AlgodConfig
	if len(networks) > 0 {
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
