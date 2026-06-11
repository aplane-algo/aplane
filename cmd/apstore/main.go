// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"flag"
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"os"

	"github.com/aplane-algo/aplane/internal/auth"
	bootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/version"

	"golang.org/x/sys/unix"
)

// Global config for commands that need it
var config serverconfig.ServerConfig

// dataDirectory holds the resolved data directory path
var dataDirectory string

func keystorePaths() storepaths.Paths {
	return storepaths.NewPaths(dataDirectory)
}

func productIdentityID() string {
	return auth.CurrentProductIdentityID()
}

func main() {
	// Handle early-exit flags before any other processing
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-version" {
			fmt.Printf("apstore %s\n", version.String())
			os.Exit(0)
		}
	}

	flag.Usage = apstoreUsage

	dataDir := flag.String("d", "", "Data directory (required, or set APSIGNER_DATA)")
	flag.Parse()

	resolvedDataDir, err := bootstrap.ResolveDataDir(*dataDir)
	if err != nil {
		logErrorf("%v", err)
		logErrorf("use -d <path> or set APSIGNER_DATA environment variable")
		os.Exit(apstoreExitUsage)
	}
	dataDirectory = resolvedDataDir

	// Check data directory is accessible
	if err := unix.Access(dataDirectory, unix.R_OK|unix.X_OK); err != nil {
		logErrorf("cannot access data directory: %s", dataDirectory)
		if os.IsPermission(err) {
			logWarnf("you may need to log out and back in for group membership to take effect")
		}
		os.Exit(apstoreExitUsage)
	}

	startup, err := bootstrap.Load(*dataDir)
	if err != nil {
		logErrorf("%v", err)
		logErrorf("use -d <path> or set APSIGNER_DATA environment variable")
		os.Exit(apstoreExitUsage)
	}
	dataDirectory = startup.DataDir
	config = startup.Config

	// Register all providers (must be called before using any registries)
	RegisterProviders()

	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(apstoreExitUsage)
	}

	dispatchApstoreCommand(args)
}
