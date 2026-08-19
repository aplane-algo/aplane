// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"flag"
	"fmt"
	"os"

	bootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
	"github.com/aplane-algo/aplane/internal/serverconfig"
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
	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(apstoreExitUsage)
	}
	if isExternalFileOnlyCommand(args) {
		config = serverconfig.DefaultServerConfig()
		RegisterProviders()
		dispatchApstoreCommand(args)
		return
	}

	resolvedDataDir, err := bootstrap.ResolveDataDir(*dataDir)
	if err != nil {
		logErrorf("%v", err)
		logErrorf("use -d <path> or set APSIGNER_DATA environment variable")
		os.Exit(apstoreExitUsage)
	}
	dataDirectory = resolvedDataDir
	if isStorePermissionCommand(args) {
		dispatchApstoreCommand(args)
		return
	}

	// Check data directory is accessible
	if err := unix.Access(dataDirectory, unix.R_OK|unix.X_OK); err != nil {
		logErrorf("cannot access data directory: %s", dataDirectory)
		if os.IsPermission(err) {
			logWarnf("signer stores are private; operating-system group membership grants IPC socket access, not store traversal")
			logWarnf("use apadmin for running-daemon operations, or follow the documented stopped-service rescue procedure as the store owner/root")
		}
		os.Exit(apstoreExitUsage)
	}

	startup, err := bootstrap.LoadResolved(resolvedDataDir)
	if err != nil {
		logErrorf("%v", err)
		logErrorf("use -d <path> or set APSIGNER_DATA environment variable")
		os.Exit(apstoreExitUsage)
	}
	config = startup.Config
	// Register all providers (must be called before using any registries)
	RegisterProviders()

	dispatchApstoreCommand(args)
}
