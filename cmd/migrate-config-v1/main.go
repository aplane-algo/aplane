// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv("APCLIENT_DATA")))
}

func run(args []string, stdout, stderr io.Writer, defaultDataDir string) int {
	var dataDir string
	var dryRun bool
	var printVersion bool

	fs := flag.NewFlagSet("migrate-config-v1", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&dataDir, "d", defaultDataDir, "apclient data directory")
	fs.BoolVar(&dryRun, "dry-run", false, "report what would be written without changing files")
	fs.BoolVar(&printVersion, "version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if printVersion {
		fmt.Fprintf(stdout, "migrate-config-v1 %s\n", version.String())
		return 0
	}
	if fs.NArg() != 0 {
		usage(stderr)
		return 2
	}
	if dataDir == "" {
		fmt.Fprintln(stderr, "migrate-config-v1: apclient data directory is required; pass -d <path> or set APCLIENT_DATA")
		return 2
	}

	needed, err := config.StoredClientPrimaryEndpointMaterializationNeeded(dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "migrate-config-v1: %v\n", err)
		return 1
	}
	if !needed {
		fmt.Fprintf(stdout, "No legacy client endpoint migration needed for %s.\n", dataDir)
		return 0
	}

	if dryRun {
		registry, changed, err := config.MaterializeStoredClientPrimaryEndpointPlan(dataDir)
		if err != nil {
			fmt.Fprintf(stderr, "migrate-config-v1: %v\n", err)
			return 1
		}
		if !changed {
			fmt.Fprintf(stdout, "No legacy client endpoint migration needed for %s.\n", dataDir)
			return 0
		}
		fmt.Fprintf(stdout, "Would write %s with primary signer endpoint.\n", config.GetClientEndpointsPath(dataDir))
		printPrimaryEndpoint(stdout, registry)
		return 0
	}

	registry, changed, err := config.MaterializeStoredClientPrimaryEndpoint(dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "migrate-config-v1: %v\n", err)
		return 1
	}
	if !changed {
		fmt.Fprintf(stdout, "No legacy client endpoint migration needed for %s.\n", dataDir)
		return 0
	}
	fmt.Fprintf(stdout, "Wrote %s with primary signer endpoint.\n", config.GetClientEndpointsPath(dataDir))
	fmt.Fprintln(stdout, "Left config.yaml unchanged.")
	printPrimaryEndpoint(stdout, registry)
	return 0
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: migrate-config-v1 [-d <apclient-data>] [--dry-run]")
}

func printPrimaryEndpoint(w io.Writer, registry config.ClientEndpointRegistry) {
	alias, endpoint, ok := registry.DefaultEndpoint()
	if !ok {
		return
	}
	fmt.Fprintf(w, "  alias:       %s\n", alias)
	fmt.Fprintf(w, "  role:        %s\n", endpoint.Role)
	fmt.Fprintf(w, "  url:         %s\n", endpoint.URL)
	fmt.Fprintf(w, "  signer_port: %d\n", endpoint.SignerPort)
	fmt.Fprintf(w, "  token_file:  %s\n", endpoint.TokenFile)
}
