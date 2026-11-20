// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// appass manages passphrase auto-unlock configuration for apsigner.
// It provides a TUI for inspecting current state, setting up auto-unlock
// (passfile or systemd-creds), and clearing configuration.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	bootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
	"github.com/aplane-algo/aplane/internal/theme"
	"github.com/aplane-algo/aplane/internal/version"
)

type appassOptions struct {
	dataDir string
	version bool
	check   bool
}

func parseAppassOptions(args []string) (appassOptions, error) {
	var opts appassOptions
	flags := flag.NewFlagSet("appass", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.dataDir, "d", "", "signer data directory")
	flags.BoolVar(&opts.version, "version", false, "print version")
	flags.BoolVar(&opts.check, "check", false, "check execution mode")
	if err := flags.Parse(args); err != nil {
		return appassOptions{}, err
	}
	if flags.NArg() != 0 {
		return appassOptions{}, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	return opts, nil
}

func main() {
	opts, err := parseAppassOptions(os.Args[1:])
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	if opts.version {
		fmt.Printf("appass %s\n", version.String())
		return
	}

	// --check runs the mode-detection / ownership gate non-interactively and
	// exits. No TUI launch, no signer-stopped requirement. Used by the
	// docker-systemd smoke test to assert systemd-install consistency.
	checkMode := opts.check
	dataDir := opts.dataDir

	resolvedDataDir, err := bootstrap.ResolveDataDir(dataDir)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		_, _ = fmt.Fprintln(os.Stderr, "Use -d <path> or set APSIGNER_DATA environment variable")
		os.Exit(1)
	}
	dataDir = resolvedDataDir

	prodManaged, err := bootstrap.IsProductionManagedDataDir(dataDir)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if err := bootstrap.EnforceExecutionMode("appass", dataDir, prodManaged, os.Geteuid(), nil); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var svc *serviceInfo
	isLocal := !prodManaged
	if prodManaged {
		var resolvedLocal bool
		svc, resolvedLocal = resolveServiceInfo()
		if resolvedLocal {
			_, _ = fmt.Fprintf(os.Stderr, "Error: systemd-managed data directory %s is marked with .prod, but no apsigner systemd service file was found\n", dataDir)
			os.Exit(1)
		}
		if err := bindManagedServicePrincipal(dataDir, svc); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	} else {
		svc = localServiceInfo()
	}
	if err := enforceModeOwnershipPolicy(dataDir, isLocal, svc); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if checkMode {
		mode := "systemd"
		if isLocal {
			mode = "local"
		}
		fmt.Printf("appass: %s is consistent with %s mode\n", dataDir, mode)
		os.Exit(0)
	}

	if err := requireSignerStopped(dataDir); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Initialize theme
	theme.Init("auto")

	// Launch TUI
	model := NewModel(dataDir, svc, isLocal)
	p := tea.NewProgram(model, tea.WithAltScreen())

	final, err := p.Run()
	// Whatever ended the program, a passphrase still typed into a form is
	// zeroed before exit.
	if finalModel, ok := final.(Model); ok {
		finalModel.clearPassphrases()
	}
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
