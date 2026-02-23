// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

// Configuration and connection commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/util"
)

func (r *REPLState) cmdNetwork(args []string, _ interface{}) error {
	return r.setNetwork(args)
}

func (r *REPLState) cmdWrite(args []string, _ interface{}) error {
	return r.toggleWriteMode(args)
}

func (r *REPLState) cmdVerbose(args []string, _ interface{}) error {
	return r.toggleVerbose(args)
}

func (r *REPLState) cmdSimulate(args []string, _ interface{}) error {
	return r.toggleSimulate(args)
}

func (r *REPLState) cmdSetenv(args []string, _ interface{}) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: setenv <name> <value>")
	}
	name := args[0]
	value := strings.Join(args[1:], " ")
	if err := os.Setenv(name, value); err != nil {
		return fmt.Errorf("failed to set environment variable: %w", err)
	}
	fmt.Printf("%s=%s\n", name, value)
	return nil
}

func (r *REPLState) cmdConnect(args []string, _ interface{}) error {
	// If no arguments, use connection from config
	if len(args) == 0 {
		// Check if SSH config exists with a remote (non-localhost) host
		if r.Config.SSH != nil && r.Config.SSH.Host != "localhost" && r.Config.SSH.Host != "127.0.0.1" {
			// Use SSH tunnel for remote connection
			fmt.Printf("Using configured SSH connection: %s (SSH: %d, signer: %d)\n",
				r.Config.SSH.Host, r.Config.SSH.Port, r.Config.SignerPort)
			return r.connectTunnelWithKey(r.Config.SSH.Host, r.Config.SSH.Port, r.Config.SignerPort)
		}
		// Direct connection to localhost (SSH config with localhost host uses direct,
		// but SSH remains available for token provisioning via 'request-token')
		hostPort := fmt.Sprintf("localhost:%d", r.Config.SignerPort)
		fmt.Printf("Connecting directly to %s...\n", hostPort)
		return r.connectDirect(hostPort)
	}

	// Parse connection string from args
	connStr := strings.Join(args, " ")
	parsed, err := util.ParseConnectionString(connStr)
	if err != nil {
		return fmt.Errorf("invalid connection: %w\n\n"+
			"Usage: connect <host> [--ssh-port <port>] [--signer-port <port>]\n\n"+
			"Remote connections use SSH tunnel. Local connections are direct.\n\n"+
			"Examples:\n"+
			"  connect                                    (use config.yaml)\n"+
			"  connect 192.168.1.100                      (defaults: SSH %d, signer %d)\n"+
			"  connect 192.168.1.100 --ssh-port 2222      (custom SSH port)\n"+
			"  connect 192.168.1.100 --signer-port 9999   (custom signer REST port)\n"+
			"  connect localhost                          (direct, no tunnel)\n"+
			"  connect localhost --signer-port 9999       (direct to custom port)\n\n"+
			"Setup:\n"+
			"  Run 'request-token' to obtain a token from the Signer",
			err, util.DefaultSSHPort, util.DefaultRESTPort)
	}

	// Check if target is localhost - if so, connect directly (no SSH needed)
	isLocalhost := parsed.Host == "localhost" || parsed.Host == "127.0.0.1" || parsed.Host == "::1"

	if isLocalhost {
		// Direct connection for localhost (token auth only, no SSH tunnel)
		hostPort := fmt.Sprintf("%s:%d", parsed.Host, parsed.SignerPort)
		fmt.Printf("Connecting directly to %s (no SSH tunnel)...\n", hostPort)
		return r.connectDirect(hostPort)
	}

	// Remote connection - use SSH tunnel
	fmt.Printf("Connecting via SSH tunnel to %s (SSH port: %d, signer port: %d)...\n",
		parsed.Host, parsed.SSHPort, parsed.SignerPort)

	return r.connectTunnelWithKey(parsed.Host, parsed.SSHPort, parsed.SignerPort)
}

func (r *REPLState) cmdRequestToken(args []string, _ interface{}) error {
	// Parse connection info
	if len(args) == 0 {
		// Use config if available
		if r.Config.SSH != nil {
			return r.requestToken(r.Config.SSH.Host, r.Config.SSH.Port)
		}
		return fmt.Errorf("usage: request-token <host> [--ssh-port <port>]\n\n" +
			"Request an API token from the Signer. Requires an operator\n" +
			"(apadmin) to approve the request on the server.\n\n" +
			"Examples:\n" +
			"  request-token 192.168.1.100\n" +
			"  request-token 192.168.1.100 --ssh-port 2222")
	}

	// Parse connection string
	connStr := strings.Join(args, " ")
	parsed, err := util.ParseConnectionString(connStr)
	if err != nil {
		return fmt.Errorf("invalid connection: %w", err)
	}

	return r.requestToken(parsed.Host, parsed.SSHPort)
}

func (r *REPLState) cmdScript(args []string, _ interface{}) error {
	return r.runScript(args)
}

func (r *REPLState) cmdConfig(_ []string, _ interface{}) error {
	// Display current config
	util.DisplayConfig(r.DataDir)
	fmt.Println("Note: Config is read-only. Edit config.yaml in the data directory manually.")
	return nil
}

func (r *REPLState) cmdPlugins(args []string, _ interface{}) error {
	disc := discovery.New()
	plugins, err := disc.Discover()
	if err != nil {
		return fmt.Errorf("failed to discover plugins: %w", err)
	}

	if len(plugins) == 0 {
		fmt.Println("No external plugins found")
		return nil
	}

	// If a specific plugin name is given, show detailed info
	if len(args) == 1 {
		pluginName := args[0]
		for _, plugin := range plugins {
			if plugin.Manifest.Name == pluginName {
				fmt.Printf("%s v%s\n", plugin.Manifest.Name, plugin.Manifest.Version)
				if plugin.Manifest.Description != "" {
					fmt.Printf("  %s\n", plugin.Manifest.Description)
				}
				if plugin.Manifest.Author != "" {
					fmt.Printf("  Author: %s\n", plugin.Manifest.Author)
				}
				if len(plugin.Manifest.Networks) > 0 {
					fmt.Printf("  Networks: %s\n", strings.Join(plugin.Manifest.Networks, ", "))
				}
				fmt.Println("  Commands:")
				for _, cmd := range plugin.Manifest.Commands {
					fmt.Printf("    %s - %s\n", cmd.Name, cmd.Description)
					if cmd.Usage != "" {
						fmt.Printf("      Usage: %s\n", cmd.Usage)
					}
				}
				return nil
			}
		}
		return fmt.Errorf("plugin not found: %s", pluginName)
	}

	// List all plugins
	fmt.Printf("External Plugins (%d):\n", len(plugins))
	for _, plugin := range plugins {
		// Collect command names
		var cmdNames []string
		for _, cmd := range plugin.Manifest.Commands {
			cmdNames = append(cmdNames, cmd.Name)
		}

		fmt.Printf("  %s v%s", plugin.Manifest.Name, plugin.Manifest.Version)
		if plugin.Manifest.Description != "" {
			fmt.Printf(" - %s", plugin.Manifest.Description)
		}
		fmt.Println()
		fmt.Printf("    Commands: %s\n", strings.Join(cmdNames, ", "))
		if len(plugin.Manifest.Networks) > 0 {
			fmt.Printf("    Networks: %s\n", strings.Join(plugin.Manifest.Networks, ", "))
		}
	}
	return nil
}
