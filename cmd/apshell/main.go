// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/manifest"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/util"
	"github.com/aplane-algo/aplane/internal/version"
)

func main() {
	// Define all flags upfront before parsing
	printVersion := flag.Bool("version", false, "Print version and exit")
	printManifest := flag.Bool("print-manifest", false, "Print provider manifest (JSON) for auditing and exit")
	dataDir := flag.String("d", "", "Data directory (default: ~/.apclient or APCLIENT_DATA)")
	network := flag.String("network", "", "Algorand network (mainnet, testnet, betanet)")
	scriptFile := flag.String("script", "", "Execute script file and exit")
	jsScript := flag.String("js", "", "Execute JavaScript script file (use '-' for stdin)")
	jsExpr := flag.String("e", "", "Execute JavaScript expression")
	flag.Parse()

	// Handle early-exit flags
	if *printVersion {
		fmt.Printf("apshell %s\n", version.String())
		os.Exit(0)
	}
	if *printManifest {
		manifest.PrintAndExit()
	}

	// Resolve data directory: -d flag > APCLIENT_DATA env var > ~/.apclient
	resolvedDataDir := util.RequireClientDataDir(*dataDir)

	// Check that data directory and config file exist
	configPath := util.GetConfigPath(resolvedDataDir)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: Config file not found: %s\n", configPath)
		fmt.Fprintln(os.Stderr, "Use -d <path> or set APCLIENT_DATA to a directory containing config.yaml")
		os.Exit(1)
	}

	// Set cache directory to be under the data directory
	util.SetCacheBaseDir(resolvedDataDir)

	// Initialize logger (supports APSHELL_DEBUG environment variable)
	util.InitLogger()

	// Register all providers (must be called before using any registries)
	RegisterProviders()

	ensureProviders()

	// Verify providers are registered (warn only if missing)
	if len(signing.GetRegisteredFamilies()) == 0 {
		fmt.Fprintf(os.Stderr, "WARNING: No signature providers registered\n")
	}

	// Load config file from data directory
	config, err := util.LoadConfig(resolvedDataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Invalid configuration: %v\n", err)
		os.Exit(1)
	}

	// Use config default if -network not specified
	selectedNetwork := *network
	if selectedNetwork == "" {
		selectedNetwork = config.Network
	}

	// Validate network is valid
	validNetworks := map[string]bool{
		"mainnet": true,
		"testnet": true,
		"betanet": true,
	}
	if !validNetworks[selectedNetwork] {
		fmt.Printf("Error: Invalid network '%s'. Valid options: mainnet, testnet, betanet\n", selectedNetwork)
		os.Exit(1)
	}

	// Validate network is allowed by config
	if !config.IsNetworkAllowed(selectedNetwork) {
		fmt.Printf("Error: Network '%s' is not allowed by configuration.\n", selectedNetwork)
		fmt.Printf("Allowed networks: %v\n", config.NetworksAllowed)
		os.Exit(1)
	}

	// Validate required configuration
	if err := validateStartup(&config, selectedNetwork); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Run script or start interactive REPL
	if *jsExpr != "" {
		runJSExpression(selectedNetwork, config, *jsExpr)
	} else if *jsScript != "" {
		runJSScriptMode(selectedNetwork, config, *jsScript)
	} else if *scriptFile != "" {
		runScriptMode(selectedNetwork, config, *scriptFile)
	} else {
		startREPL(selectedNetwork, config)
	}
}

// ensureProviders validates that required providers are registered.
// Uses dynamic registry queries instead of hard-coded provider lists.
func ensureProviders() {
	// Verify at least one LogicSig DSA is registered
	if len(logicsigdsa.GetAll()) == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "Error: no LogicSig DSAs registered - check providers.go imports\n")
		os.Exit(1)
	}
}
