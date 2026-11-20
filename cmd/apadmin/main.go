// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	bootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
	"github.com/aplane-algo/aplane/internal/bootstrap/signeradmin"
	"github.com/aplane-algo/aplane/internal/clientlog"
	"github.com/aplane-algo/aplane/internal/manifest"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	tui "github.com/aplane-algo/aplane/internal/signerapp/signertui"
	"github.com/aplane-algo/aplane/internal/theme"
	"github.com/aplane-algo/aplane/internal/version"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	if err := validateFlagSpelling(os.Args[1:]); err != nil {
		printBatchError(os.Stderr, err)
		os.Exit(2)
	}

	// Handle early-exit flags before any other processing
	for _, arg := range os.Args[1:] {
		if arg == "--version" {
			fmt.Printf("apadmin %s\n", version.String())
			os.Exit(0)
		}
	}

	clientlog.Install(clientlog.StartLevel(slog.LevelWarn), clientlog.WriterSink(os.Stderr))

	// Register all providers (must be called before manifest or any registry queries)
	RegisterProviders()

	for _, arg := range os.Args[1:] {
		if arg == "--print-manifest" {
			manifest.PrintAndExit()
		}
	}

	// Define flags
	dataDir := flag.String("d", "", "Signer data directory for same-UID mode (or set APSIGNER_DATA)")
	ipcPathFlag := flag.String("ipc-path", "", "Admin IPC socket path (or set APSIGNER_IPC_PATH)")
	initTestFlag()
	flag.Parse()

	positional := flag.Args()
	globals := adminBatchGlobalOptions{dataDir: *dataDir, ipcPath: *ipcPathFlag}
	streams := adminBatchStreams{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr}
	switch classifyProductionSubcommand(positional) {
	case productionPolicy:
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "ipc-path" {
				globals.ipcPathPassed = true
			}
		})
		code := runPolicyCommand(context.Background(), positional[1:], globals, streams)
		if code != 0 {
			os.Exit(code)
		}
		return
	case productionCatalog:
		code := runCatalogCommand(positional[0], positional[1:], globals, streams)
		if code != 0 {
			os.Exit(code)
		}
		return
	case productionStore:
		code := runStoreCommand(positional[0], positional[1:], globals, streams)
		if code != 0 {
			os.Exit(code)
		}
		return
	}

	resolvedDataDir, ipcPath, err := resolveIPCPath(globals)
	if err != nil {
		logErrorf("%v", err)
		os.Exit(1)
	}

	config := serverconfig.DefaultServerConfig()
	if resolvedDataDir != "" && unix.Access(resolvedDataDir, unix.R_OK|unix.X_OK) == nil {
		startup, err := bootstrap.LoadResolved(resolvedDataDir)
		if err != nil {
			logErrorf("%v", err)
			os.Exit(1)
		}
		config = startup.Config
	}
	// Detect the terminal's background until the signer reports the theme
	// saved in its settings.
	theme.Init("auto")

	// Configure algod client on DSA providers for TEAL compilation
	signeradmin.ConfigureAlgodOnDSAs(config, logWarnf)

	if err := signeradmin.EnsureProviders(); err != nil {
		logErrorf("%v", err)
		os.Exit(1)
	}

	// Check for test mode (only available in test builds with -tags testmode)
	if isTestMode() {
		runTestMode(ipcPath, positional)
		return
	}

	startTUI(tui.LocalIPCConnector{Path: ipcPath})
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
func startTUI(connector tui.AdminConnector) {
	// Nothing may write to the terminal while the TUI owns it. Diagnostics wait
	// for it to finish; the lost-notification count is shown live, in the TUI.
	logs := clientlog.NewDeferred()
	clientlog.SetSink(logs)

	// Create and run the TUI
	model := tui.NewModel(connector, "").WithStandalone()
	p := tea.NewProgram(model, tea.WithAltScreen())

	final, err := p.Run()
	// stderr is the only channel left if this fails.
	_ = logs.Close(os.Stderr)
	// Whatever ended the program, release what an unfinished backup transfer
	// holds (a staging file, an open archive, a passphrase).
	if m, ok := final.(tui.Model); ok {
		m.Shutdown()
	}
	if err != nil {
		logErrorf("error running TUI: %v", err)
		os.Exit(1)
	}
}
