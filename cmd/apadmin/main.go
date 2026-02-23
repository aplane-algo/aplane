// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/cmd/apadmin/internal/tui"
	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/manifest"
	"github.com/aplane-algo/aplane/internal/mnemonic"
	"github.com/aplane-algo/aplane/internal/util"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"
	"github.com/aplane-algo/aplane/internal/version"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	tea "github.com/charmbracelet/bubbletea"
)

// Command line flags (defined after config load in main)
var (
	serverAddr *string
	batchMode  *bool
	storeDir   *string
)

func main() {
	// Handle early-exit flags before any other processing
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-version" {
			fmt.Printf("apadmin %s\n", version.String())
			os.Exit(0)
		}
		if arg == "--print-manifest" || arg == "-print-manifest" {
			manifest.PrintAndExit()
		}
	}

	// Define flags
	dataDir := flag.String("d", "", "Data directory (required, or set APSIGNER_DATA)")
	batchMode = flag.Bool("batch", false, "Run in batch mode (non-interactive)")
	flag.Parse()

	// Resolve data directory from -d flag or APSIGNER_DATA env var
	resolvedDataDir := util.RequireSignerDataDir(*dataDir)

	// Load config from data directory
	config := util.LoadServerConfig(resolvedDataDir)
	defaultAddr := fmt.Sprintf("localhost:%d", config.SignerPort)
	serverAddr = &defaultAddr

	// Use store from config
	storeDir = &config.StoreDir

	// Validate store directory is specified
	if *storeDir == "" {
		fmt.Fprintln(os.Stderr, "Error: store must be specified in config.yaml")
		os.Exit(1)
	}

	// Set the global keystore path for template scanning
	utilkeys.SetKeystorePath(*storeDir)

	// Register all providers (must be called before using any registries)
	RegisterProviders()

	// Configure algod client on DSA providers for TEAL compilation
	configureAlgodOnDSAs(config)

	if err := ensureProviders(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Plugin audit: Log all registered providers at startup
	fmt.Println("ApAdmin - Key Management Tool")
	fmt.Println("===================================")

	// Check registered key generators
	keyGens := keygen.GetRegisteredFamilies()
	if len(keyGens) > 0 {
		fmt.Printf("✓ Key generators: %v\n", keyGens)
	} else {
		fmt.Printf("⚠ WARNING: No key generators (check plugins.go)\n")
	}

	// Check registered mnemonic handlers
	mnemonics := mnemonic.GetRegisteredFamilies()
	if len(mnemonics) > 0 {
		fmt.Printf("✓ Mnemonic handlers: %v\n", mnemonics)
	}

	// Check algorithm metadata
	algorithms := algorithm.GetRegisteredFamilies()
	if len(algorithms) > 0 {
		fmt.Printf("✓ Algorithm metadata: %v\n", algorithms)
	}

	fmt.Println("-----------------------------------")

	// Check for batch mode
	if *batchMode {
		runBatchMode(config, *serverAddr, *storeDir, flag.Args())
		return
	}

	startTUI(config, resolvedDataDir)
}

// startTUI launches the Bubble Tea TUI application
func startTUI(config util.ServerConfig, dataDir string) {
	fmt.Printf("Connecting to Signer via IPC (%s)...\n", config.IPCPath)

	// Create and run the TUI
	model := tui.NewModel(config.IPCPath, dataDir)
	p := tea.NewProgram(model, tea.WithAltScreen())

	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running TUI: %v\n", err)
		os.Exit(1)
	}
}

// ensureProviders validates that required providers are registered.
// Uses dynamic registry queries instead of hard-coded provider lists.
func ensureProviders() error {
	if len(keygen.GetRegisteredFamilies()) == 0 {
		return fmt.Errorf("no key generators registered - check providers.go imports")
	}
	if len(mnemonic.GetRegisteredFamilies()) == 0 {
		return fmt.Errorf("no mnemonic handlers registered - check providers.go imports")
	}
	if len(algorithm.GetRegisteredFamilies()) == 0 {
		return fmt.Errorf("no algorithm metadata registered - check providers.go imports")
	}
	return nil
}

// configureAlgodOnDSAs sets up the algod client on all DSA providers that support it.
// This enables runtime TEAL compilation for composed providers during key generation.
func configureAlgodOnDSAs(config util.ServerConfig) {
	algodURL := config.TEALCompilerAlgodURL
	algodToken := config.TEALCompilerAlgodToken

	if algodURL == "" {
		fmt.Println("⚠  No teal_compiler_algod_url configured - composed Falcon templates unavailable")
		return
	}

	client, err := algod.MakeClient(algodURL, algodToken)
	if err != nil {
		fmt.Printf("⚠  Failed to create algod client: %v\n", err)
		fmt.Println("   Composed Falcon templates will be unavailable")
		return
	}

	logicsigdsa.ConfigureAlgodClient(client)
	fmt.Println("✓ TEAL compiler configured")
}
