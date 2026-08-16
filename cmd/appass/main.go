// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// appass manages passphrase auto-unlock configuration for apsigner.
// It provides a TUI for inspecting current state, setting up auto-unlock
// (passfile or systemd-creds), and clearing configuration.
package main

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	bootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
	"github.com/aplane-algo/aplane/internal/theme"
	"github.com/aplane-algo/aplane/internal/version"
)

var currentEUID = os.Geteuid

func main() {
	args := os.Args[1:]
	if err := rejectRemovedIdentityFlag(args); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	// Handle --version early
	for _, arg := range args {
		if arg == "--version" || arg == "-version" {
			fmt.Printf("appass %s\n", version.String())
			os.Exit(0)
		}
	}

	// --check runs the mode-detection / ownership gate non-interactively and
	// exits. No TUI launch, no signer-stopped requirement. Used by the
	// docker-systemd smoke test to assert systemd-install consistency.
	var checkMode bool
	for _, arg := range args {
		if arg == "--check" || arg == "-check" {
			checkMode = true
			break
		}
	}

	// Parse flags manually.
	var dataDir string
	for i := 0; i < len(args)-1; i++ {
		switch args[i] {
		case "-d":
			dataDir = args[i+1]
		}
	}

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
	if err := enforceAppassExecutionMode(dataDir, prodManaged); err != nil {
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
	if err := enforceModeOwnershipPolicy(dataDir, productIdentityID(), isLocal, svc); err != nil {
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

	if _, err := p.Run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func enforceAppassExecutionMode(dataDir string, prodManaged bool) error {
	switch {
	case prodManaged && currentEUID() != 0:
		return fmt.Errorf(
			"systemd-managed data directory %s requires root for appass; run:\n  %s",
			dataDir,
			appassInvocation(true, dataDir),
		)
	case !prodManaged && currentEUID() == 0:
		return fmt.Errorf(
			"local signer data directory %s must not be managed as root; rerun without sudo:\n  %s",
			dataDir,
			appassInvocation(false, dataDir),
		)
	default:
		return nil
	}
}

func appassInvocation(useSudo bool, dataDir string) string {
	parts := []string{"appass", "-d", dataDir}
	if useSudo {
		parts = append([]string{"sudo"}, parts...)
	}
	for i := range parts {
		parts[i] = shellQuoteArg(parts[i])
	}
	return strings.Join(parts, " ")
}

func rejectRemovedIdentityFlag(args []string) error {
	for _, arg := range args {
		if arg == "-identity" || arg == "--identity" || strings.HasPrefix(arg, "-identity=") || strings.HasPrefix(arg, "--identity=") {
			return fmt.Errorf("-identity is no longer supported; appass manages the product identity")
		}
	}
	return nil
}

func isShellSafeRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	}
	return strings.ContainsRune("@%_+=:,./-", r)
}

func shellQuoteArg(s string) string {
	if s == "" {
		return "''"
	}
	for _, r := range s {
		if isShellSafeRune(r) {
			continue
		}
		return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
	}
	return s
}

// detectMethod inspects PassphraseCommandArgv to determine the current auto-unlock method.
func detectMethod(argv []string) string {
	if len(argv) == 0 {
		return "none"
	}
	bin := argv[0]
	switch {
	case strings.HasSuffix(bin, "/appass-file") || bin == "appass-file":
		return "passfile"
	case strings.HasSuffix(bin, "/appass-systemd-creds") || bin == "appass-systemd-creds":
		return "systemd-creds"
	default:
		return "custom"
	}
}
