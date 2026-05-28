// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/config"
)

// SwitchNetworkRequest changes the active Algorand network.
type SwitchNetworkRequest struct {
	Network string
}

// SwitchNetwork changes the active Algorand network and updates dependent
// application services such as plugins.
func (a *App) SwitchNetwork(_ context.Context, req SwitchNetworkRequest) (*SwitchNetworkResult, error) {
	if err := config.ValidateNetworkID(req.Network); err != nil {
		return nil, err
	}
	if !a.Config.IsNetworkAllowed(req.Network) {
		return nil, fmt.Errorf("network '%s' is not allowed by configuration.\nAllowed networks: %v", req.Network, a.Config.NetworksAllowed)
	}

	algodClient, err := algo.GetAlgodClientWithConfig(req.Network, &a.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", req.Network, err)
	}

	oldNetwork := a.eng.GetNetwork()
	if err := a.eng.SetNetwork(req.Network, algodClient); err != nil {
		return nil, err
	}

	if a.Plugins != nil {
		algodURL, algodToken := getAlgodConfig(a.Config.Algod, req.Network)
		a.Plugins.SetConfig(req.Network, algodURL, algodToken, "")
		a.Plugins.StopAll()
	}

	return &SwitchNetworkResult{
		OldNetwork: oldNetwork,
		NewNetwork: req.Network,
		Summary: Summary{
			Message: fmt.Sprintf("Switched to %s", req.Network),
		},
	}, nil
}

// getAlgodConfig returns the algod URL and token for the given network.
// Returns empty strings if not configured in config.yaml.
func getAlgodConfig(algod config.AlgodConfig, network string) (string, string) {
	if cfg, err := algod.GetNetwork(network); err == nil && cfg.Server != "" {
		return cfg.Server, cfg.Token
	}
	return "", ""
}
