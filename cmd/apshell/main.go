// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/apshellcli"
	bootstrap "github.com/aplane-algo/aplane/internal/bootstrap/shell"
	"github.com/aplane-algo/aplane/internal/manifest"
	"github.com/aplane-algo/aplane/internal/theme"
	"github.com/aplane-algo/aplane/internal/version"
)

func main() {
	// Define all flags upfront before parsing
	printVersion := flag.Bool("version", false, "Print version and exit")
	printManifest := flag.Bool("print-manifest", false, "Print provider manifest (JSON) for auditing and exit")
	dataDir := flag.String("d", "", "Data directory (required; or set APCLIENT_DATA)")
	networkLong := flag.String("network", "", "Network context token")
	networkShort := flag.String("n", "", "Network context token")
	mcpMode := flag.Bool("mcp", false, "Run as MCP server (stdio transport)")
	scriptFile := flag.String("script", "", "Execute script file and exit")
	jsScript := flag.String("js", "", "Execute JavaScript script file (use '-' for stdin)")
	jsExpr := flag.String("e", "", "Execute JavaScript expression")
	flag.Parse()

	// Handle early-exit flags
	if *printVersion {
		fmt.Printf("apshell %s\n", version.String())
		os.Exit(0)
	}

	// Register all providers (must be called before manifest or any registry queries)
	apshellcli.RegisterProviders()
	if err := apshellcli.EnsureProviders(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *printManifest {
		manifest.PrintAndExit()
	}

	network, err := apshellcli.ResolveNetworkOverride(*networkLong, *networkShort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	startup, err := bootstrap.Load(*dataDir, network)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintln(os.Stderr, "Use -d <path> or set APCLIENT_DATA to a directory containing config.yaml")
		os.Exit(1)
	}

	// Initialize color theme based on config
	theme.Init(startup.Config.Theme)

	// Run in the selected mode
	if *mcpMode {
		apshellcli.RunMCPMode(startup.Network, startup.Config, startup.DataDir)
	} else if *jsExpr != "" {
		apshellcli.RunJSExpression(startup.Network, startup.Config, startup.DataDir, *jsExpr)
	} else if *jsScript != "" {
		apshellcli.RunJSScriptMode(startup.Network, startup.Config, startup.DataDir, *jsScript)
	} else if *scriptFile != "" {
		apshellcli.RunScriptMode(startup.Network, startup.Config, startup.DataDir, *scriptFile)
	} else {
		apshellcli.StartREPL(startup.Network, startup.Config, startup.DataDir)
	}
}
