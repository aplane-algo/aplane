// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/util"
)

// setNetwork changes the active Algorand network (mainnet/testnet/betanet)
func (r *REPLState) setNetwork(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: network <mainnet|testnet|betanet>")
	}

	network := args[0]
	if network != "mainnet" && network != "testnet" && network != "betanet" {
		return fmt.Errorf("invalid network. Use: mainnet, testnet, or betanet")
	}

	// Check if network is allowed by config
	if !r.Config.IsNetworkAllowed(network) {
		return fmt.Errorf("network '%s' is not allowed by configuration.\nAllowed networks: %v", network, r.Config.NetworksAllowed)
	}

	r.Engine.Network = network

	var err error
	r.Engine.AlgodClient, err = algo.GetAlgodClientWithConfig(r.Engine.Network, &r.Config)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", network, err)
	}

	r.Engine.AsaCache = util.LoadASACache(r.Engine.Network)
	r.Engine.AuthCache = util.BuildAuthCache(r.Engine.AlgodClient, &r.Engine.AliasCache, &r.Engine.SignerCache, r.Engine.Network)
	r.Engine.Network = network

	// Update plugin manager with new network config
	if r.PluginManager != nil {
		var apiServer string
		switch network {
		case "mainnet":
			apiServer = "https://mainnet-api.algonode.cloud"
		case "testnet":
			apiServer = "https://testnet-api.algonode.cloud"
		case "betanet":
			apiServer = "https://betanet-api.algonode.cloud"
		}
		r.PluginManager.SetConfig(network, apiServer, "", "")
		// Stop any running plugins so they reinitialize with new network
		r.PluginManager.StopAll()
	}

	fmt.Printf("Switched to %s\n", network)
	return nil
}
