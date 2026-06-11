// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Command apsigner is the APlane signing daemon. The binary is a thin shim:
// it parses flags, registers the providers it ships with, and hands off to
// internal/signerapp/daemon, which owns the HTTP/IPC/SSH runtime.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/manifest"
	"github.com/aplane-algo/aplane/internal/signerapp/daemon"
	"github.com/aplane-algo/aplane/internal/version"
)

func main() {
	// Handle early-exit flags before any other output
	printVersion := flag.Bool("version", false, "Print version and exit")
	printManifest := flag.Bool("print-manifest", false, "Print provider manifest (JSON) for auditing and exit")
	dataDir := flag.String("d", "", "Data directory (required, or set APSIGNER_DATA)")
	flag.Parse()
	if *printVersion {
		fmt.Printf("apsigner %s\n", version.String())
		os.Exit(0)
	}

	// Register all providers (must be called before manifest or any registry queries)
	RegisterProviders()

	if *printManifest {
		manifest.PrintAndExit()
	}

	os.Exit(daemon.Run(*dataDir))
}
