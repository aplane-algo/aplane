// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"flag"
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/aplane-algo/aplane/internal/algorithm"
	bootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/manifest"
	"github.com/aplane-algo/aplane/internal/mnemonic"
	"github.com/aplane-algo/aplane/internal/noderole"
	tui "github.com/aplane-algo/aplane/internal/signerapp/signertui"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/theme"
	"github.com/aplane-algo/aplane/internal/version"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	tea "github.com/charmbracelet/bubbletea"
)

// Command line flags (defined after config load in main)
var (
	remoteMode *bool
)

func main() {
	if err := validateFlagSpelling(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "apadmin: %v\n", err)
		os.Exit(2)
	}

	// Handle early-exit flags before any other processing
	for _, arg := range os.Args[1:] {
		if arg == "--version" {
			fmt.Printf("apadmin %s\n", version.String())
			os.Exit(0)
		}
	}

	// Register all providers (must be called before manifest or any registry queries)
	RegisterProviders()

	for _, arg := range os.Args[1:] {
		if arg == "--print-manifest" {
			manifest.PrintAndExit()
		}
	}

	// Define flags
	dataDir := flag.String("d", "", "Data directory (required, or set APSIGNER_DATA)")
	clientDataDir := flag.String("client-data", "", "Client data directory for remote SSH mode (or set APCLIENT_DATA)")
	initTestFlag()
	remoteMode = flag.Bool("remote", false, "Connect to apsigner over SSH instead of local IPC")
	flag.Parse()

	if *remoteMode {
		runRemoteMode(*clientDataDir)
		return
	}

	resolvedDataDir, err := bootstrap.ResolveDataDir(*dataDir)
	if err != nil {
		logErrorf("%v", err)
		logErrorf("use -d <path> or set APSIGNER_DATA environment variable")
		os.Exit(1)
	}

	// Check data directory is accessible
	if err := unix.Access(resolvedDataDir, unix.R_OK|unix.X_OK); err != nil {
		logErrorf("cannot access data directory: %s", resolvedDataDir)
		if os.IsPermission(err) {
			logWarnf("you may need to log out and back in for group membership to take effect")
		}
		os.Exit(1)
	}

	startup, err := bootstrap.LoadResolved(resolvedDataDir)
	if err != nil {
		logErrorf("%v", err)
		logErrorf("use -d <path> or set APSIGNER_DATA environment variable")
		os.Exit(1)
	}
	config := startup.Config
	// Initialize color theme based on config
	theme.Init(config.Theme)

	// Configure algod client on DSA providers for TEAL compilation
	configureAlgodOnDSAs(config)

	if err := ensureProviders(); err != nil {
		logErrorf("%v", err)
		os.Exit(1)
	}

	// Plugin audit: Log all registered providers at startup
	logInfof("APlane Signer")
	logInfof("===================================")

	// Check registered key generators
	keyGens := keygen.GetRegisteredFamilies()
	if len(keyGens) > 0 {
		logInfof("key generators: %v", keyGens)
	} else {
		logWarnf("no key generators (check plugins.go)")
	}

	// Check registered mnemonic handlers
	mnemonics := mnemonic.GetRegisteredFamilies()
	if len(mnemonics) > 0 {
		logInfof("mnemonic handlers: %v", mnemonics)
	}

	// Check algorithm metadata
	algorithms := algorithm.GetRegisteredFamilies()
	if len(algorithms) > 0 {
		logInfof("algorithm metadata: %v", algorithms)
	}

	logInfof("-----------------------------------")

	// Check for test mode (only available in test builds with -tags testmode)
	if isTestMode() {
		runTestMode(config, flag.Args())
		return
	}

	startTUI(tui.LocalIPCConnector{Path: config.IPCPath}, resolvedDataDir)
}

func validateFlagSpelling(args []string) error {
	for _, arg := range args {
		if arg == "--" {
			return nil
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") {
			continue
		}
		if arg == "-d" || strings.HasPrefix(arg, "-d=") || arg == "-h" {
			continue
		}
		name := strings.TrimLeft(arg, "-")
		if before, _, ok := strings.Cut(name, "="); ok {
			name = before
		}
		if len(name) > 1 {
			return fmt.Errorf("long option -%s is not supported; use --%s", name, name)
		}
	}
	return nil
}

// startTUI launches the Bubble Tea TUI application
func startTUI(connector tui.AdminConnector, dataDir string) {
	logInfof("starting apadmin TUI")

	// SSH admin connections can emit status lines from background goroutines.
	// A Bubble Tea host owns the terminal, so suppress those raw writes while
	// the TUI is running.
	sshtunnel.SetStatusWriter(io.Discard)
	defer sshtunnel.SetStatusWriter(nil)

	// Create and run the TUI
	model := tui.NewModel(connector, dataDir).WithInitialNodeRole(initialNodeRole(dataDir)).WithStandalone()
	p := tea.NewProgram(model, tea.WithAltScreen())

	if _, err := p.Run(); err != nil {
		logErrorf("error running TUI: %v", err)
		os.Exit(1)
	}
}

func initialNodeRole(dataDir string) string {
	if dataDir == "" {
		return ""
	}
	doc, _, err := noderole.Load(storepaths.NewPaths(dataDir))
	if err != nil {
		return ""
	}
	return string(doc.Role)
}

func runRemoteMode(clientDataDirFlag string) {
	remoteCfg, err := loadRemoteAdminConfig(clientDataDirFlag)
	if err != nil {
		logErrorf("%v", err)
		os.Exit(1)
	}

	logInfof("connecting to signer via SSH admin subsystem (%s:%d)", remoteCfg.config.LegacySSH.Host, remoteCfg.config.LegacySSH.Port)
	if isTestMode() {
		runRemoteTestMode(remoteCfg, flag.Args())
		return
	}
	startTUI(remoteCfg.connector, remoteCfg.dataDir)
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
func configureAlgodOnDSAs(config serverconfig.ServerConfig) {
	cfg, err := config.GetTEALCompileAlgod()
	if err != nil || cfg.Server == "" {
		logWarnf("no algod.%s.server configured - composed Falcon templates unavailable", config.TEALCompileNetwork)
		return
	}

	client, err := algod.MakeClient(cfg.Server, cfg.Token)
	if err != nil {
		logWarnf("failed to create algod client: %v", err)
		logWarnf("composed Falcon templates will be unavailable")
		return
	}

	logicsigdsa.ConfigureAlgodClient(client)
	logInfof("TEAL compiler configured")
}
