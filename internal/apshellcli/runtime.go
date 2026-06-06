// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/manager"
)

func initPluginRuntime(r *REPLState) error {
	if r.app().Plugins == nil {
		r.app().Plugins = manager.NewManagerWithDataDir(r.DataDir)
	}
	if err := r.app().ConfigurePlugins(); err != nil {
		return fmt.Errorf("configure plugins: %w", err)
	}
	if _, err := r.app().Plugins.DiscoverPluginsCached(); err != nil {
		return fmt.Errorf("discover plugins: %w", err)
	}
	return nil
}

func discoverExternalPlugins(r *REPLState) ([]*discovery.Plugin, error) {
	if r.app().Plugins == nil {
		return nil, nil
	}
	return r.app().Plugins.DiscoverPluginsCached()
}

func attemptStartupConnection(r *REPLState) error {
	decision := r.app().StartupConnectDecision()
	if !decision.ShouldConnect {
		return nil
	}
	return connectConfigured(r)
}

const missingAplaneTokenStartupMessage = "No aplane token found. Run 'request-token' to obtain token from the signer."

func printInteractiveStartupConnectionStatus(r *REPLState) {
	decision := r.app().StartupConnectDecision()
	if !decision.HasToken {
		fmt.Println()
		fmt.Println(missingAplaneTokenStartupMessage)
		fmt.Println()
		return
	}
	if !decision.ShouldConnect {
		fmt.Println("Error: No default signer endpoint in endpoints.yaml.")
		fmt.Println("  Add a signer endpoint to connect.")
		return
	}

	fmt.Printf("Verifying Signer via SSH: %s (SSH port: %d, signer port: %d)\n",
		decision.Host, decision.SSHPort, decision.SignerPort)
	if err := connectConfigured(r); err != nil {
		fmt.Printf("\nWarning: Signer verification failed: %v\n", err)
		fmt.Println("Signer not available (run 'connect' to retry)")
	}
}

func shutdownRuntime(r *REPLState) {
	_ = disconnectTunnel(r)
	if r.app().Plugins != nil {
		r.app().Plugins.StopAll()
	}
	r.app().StopClientCacheWatcher()
}
