// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package shell

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/cache"
	apconfig "github.com/aplane-algo/aplane/internal/config"
)

// Startup captures the resolved apshell startup inputs after bootstrap.
type Startup struct {
	DataDir string
	Config  apconfig.Config
	Network string
}

// Load resolves apshell startup state from flags and config.
//
// This is the composition root for client-side path/config/cache setup. It keeps
// startup behavior explicit while preserving current cache package semantics.
func Load(dataDirFlag, networkFlag string) (*Startup, error) {
	dataDir := apconfig.GetClientDataDir(dataDirFlag)
	if dataDir == "" {
		return nil, fmt.Errorf("client data directory not specified: pass -d <path> or set APCLIENT_DATA")
	}

	configPath := apconfig.GetConfigPath(dataDir)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", configPath)
	}

	cache.InitLogger()

	cfg, err := apconfig.LoadConfig(dataDir)
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	network := networkFlag
	if network == "" {
		network = cfg.Network
	}
	if err := apconfig.ValidateNetworkID(network); err != nil {
		return nil, fmt.Errorf("invalid network override: %w", err)
	}
	if !cfg.IsNetworkAllowed(network) {
		return nil, fmt.Errorf("network '%s' is not allowed by configuration. Allowed networks: %v", network, cfg.NetworksAllowed)
	}

	algodConfig, err := cfg.GetAlgodConfig(network)
	if err != nil {
		return nil, fmt.Errorf("network %q is not configured in config.yaml%s", network, configuredNetworksSuffix(cfg))
	}
	if algodConfig.Server == "" {
		return nil, fmt.Errorf("algod.%s.server is required in config.yaml", network)
	}

	return &Startup{
		DataDir: dataDir,
		Config:  cfg,
		Network: network,
	}, nil
}

func configuredNetworksSuffix(cfg apconfig.Config) string {
	if len(cfg.Algod) == 0 {
		return ""
	}

	networks := make([]string, 0, len(cfg.Algod))
	for network, algodCfg := range cfg.Algod {
		if algodCfg != nil {
			networks = append(networks, network)
		}
	}
	if len(networks) == 0 {
		return ""
	}

	sort.Strings(networks)
	return fmt.Sprintf("; configured networks: %s", strings.Join(networks, ", "))
}
