// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"flag"
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"io"
	"os"
	"time"

	"github.com/aplane-algo/aplane/internal/signerprobe"
	"github.com/aplane-algo/aplane/internal/version"
)

const (
	exitRunning = 0
	exitStopped = 1
	exitUnknown = 2
)

var checkSigner = signerprobe.Check

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return exitUnknown
	}

	switch args[0] {
	case "-h", "--help", "help":
		printUsage(stdout)
		return exitRunning
	case "-version", "--version", "version":
		writef(stdout, "approbe %s\n", version.String())
		return exitRunning
	case "signer-running":
		return runSignerRunning(args[1:], stdout, stderr)
	default:
		writef(stderr, "Error: unknown command: %s\n\n", args[0])
		printUsage(stderr)
		return exitUnknown
	}
}

func runSignerRunning(args []string, stdout, stderr io.Writer) int {
	var dataDir string
	var ipcPath string
	var quiet bool
	var timeout time.Duration

	fs := flag.NewFlagSet("signer-running", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&dataDir, "d", "", "signer data directory")
	fs.StringVar(&dataDir, "data-dir", "", "signer data directory")
	fs.StringVar(&ipcPath, "ipc-path", "", "admin IPC socket path")
	fs.BoolVar(&quiet, "quiet", false, "suppress status output")
	fs.DurationVar(&timeout, "timeout", signerprobe.DefaultTimeout, "IPC connection timeout")
	fs.Usage = func() {
		writeln(stderr, "Usage: approbe signer-running -d <signer-data-dir> [--quiet] [--timeout 300ms]")
	}
	if err := fs.Parse(args); err != nil {
		return exitUnknown
	}
	if fs.NArg() != 0 {
		writef(stderr, "Error: unexpected argument: %s\n\n", fs.Arg(0))
		fs.Usage()
		return exitUnknown
	}
	dataDirExplicit := false
	fs.Visit(func(selected *flag.Flag) {
		if selected.Name == "d" || selected.Name == "data-dir" {
			dataDirExplicit = true
		}
	})

	dataDir = serverconfig.GetSignerDataDir(dataDir)

	result, err := checkSigner(dataDir, signerprobe.Options{
		Timeout: timeout, IPCPath: ipcPath, DataDirExplicit: dataDirExplicit,
	})
	if err != nil {
		if result.IPCPath != "" {
			writef(stderr, "unknown %s: %v\n", result.IPCPath, err)
		} else {
			writef(stderr, "unknown: %v\n", err)
		}
		return exitUnknown
	}

	if !quiet {
		writef(stdout, "%s %s\n", result.State, result.IPCPath)
	}
	if result.Running() {
		return exitRunning
	}
	return exitStopped
}

func printUsage(w io.Writer) {
	writeln(w, `Usage:
  approbe signer-running [-d <signer-data-dir>] [--ipc-path <socket>] [--quiet] [--timeout 300ms]
  approbe --version

Exit codes for signer-running:
  0  signer IPC is reachable
  1  signer IPC is stopped, stale, or absent
  2  probe failed or usage/configuration error`)
}

func writef(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func writeln(w io.Writer, text string) {
	_, _ = fmt.Fprintln(w, text)
}
