// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// appass manages passphrase auto-unlock configuration for apsignerd.
// It replaces the shell scripts passphrase-install.sh and systemcreds-install.sh
// with a single Go binary that can set up, inspect, and tear down auto-unlock.
//
// Usage:
//
//	sudo appass -d <data-dir> status
//	sudo appass -d <data-dir> set passfile
//	sudo appass -d <data-dir> set systemcreds
//	sudo appass -d <data-dir> clear
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/aplane-algo/aplane/internal/util"
	"github.com/aplane-algo/aplane/internal/version"
)

var dataDirectory string

func main() {
	// Handle --version before flag parsing
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-version" {
			fmt.Printf("appass %s\n", version.String())
			os.Exit(0)
		}
	}

	var dataDir string
	flag.StringVar(&dataDir, "d", "", "apsignerd data directory (or set APSIGNER_DATA)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "appass — manage passphrase auto-unlock for apsignerd\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  appass -d <data-dir> status          Show current auto-unlock method\n")
		fmt.Fprintf(os.Stderr, "  appass -d <data-dir> set passfile    Set up pass-file auto-unlock\n")
		fmt.Fprintf(os.Stderr, "  appass -d <data-dir> set systemcreds Set up systemd-creds auto-unlock\n")
		fmt.Fprintf(os.Stderr, "  appass -d <data-dir> clear           Remove auto-unlock configuration\n")
		fmt.Fprintf(os.Stderr, "  appass --version                     Show version\n")
		fmt.Fprintf(os.Stderr, "\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	dataDirectory = util.RequireSignerDataDir(dataDir)

	requireRoot()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	switch args[0] {
	case "status":
		if err := cmdStatus(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "set":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Error: 'set' requires a method: passfile or systemcreds")
			os.Exit(2)
		}
		switch args[1] {
		case "passfile":
			if err := cmdSetPassfile(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		case "systemcreds":
			if err := cmdSetSystemcreds(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		default:
			fmt.Fprintf(os.Stderr, "Error: unknown method %q (use passfile or systemcreds)\n", args[1])
			os.Exit(2)
		}
	case "clear":
		if err := cmdClear(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command %q\n", args[0])
		flag.Usage()
		os.Exit(2)
	}
}

func requireRoot() {
	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "Error: appass must be run as root (use sudo).")
		os.Exit(1)
	}
}

// detectMethod inspects PassphraseCommandArgv to determine the current auto-unlock method.
func detectMethod(argv []string) string {
	if len(argv) == 0 {
		return "none"
	}
	bin := argv[0]
	switch {
	case strings.HasSuffix(bin, "/pass-file") || bin == "pass-file":
		return "passfile"
	case strings.HasSuffix(bin, "/pass-systemd-creds") || bin == "pass-systemd-creds":
		return "systemcreds"
	default:
		return "custom"
	}
}
