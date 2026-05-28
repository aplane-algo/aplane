// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
)

// EnsureProviders validates that client-side providers were registered.
func EnsureProviders() error {
	if len(logicsigdsa.GetAll()) == 0 {
		return fmt.Errorf("no LogicSig DSAs registered - check providers.go imports")
	}
	return nil
}

// ResolveNetworkOverride resolves apshell's -network and -n flags.
func ResolveNetworkOverride(longValue, shortValue string) (string, error) {
	if longValue != "" && shortValue != "" && longValue != shortValue {
		return "", fmt.Errorf("conflicting network flags: -network=%q and -n=%q", longValue, shortValue)
	}
	if shortValue != "" {
		return shortValue, nil
	}
	return longValue, nil
}

func StartREPL(network string, cfg config.Config, dataDir string) {
	startREPL(network, cfg, dataDir)
}

func RunScriptMode(network string, cfg config.Config, dataDir string, scriptPath string) {
	runScriptMode(network, cfg, dataDir, scriptPath)
}

func RunJSScriptMode(network string, cfg config.Config, dataDir string, scriptPath string) {
	runJSScriptMode(network, cfg, dataDir, scriptPath)
}

func RunJSExpression(network string, cfg config.Config, dataDir string, expr string) {
	runJSExpression(network, cfg, dataDir, expr)
}

func RunMCPMode(network string, cfg config.Config, dataDir string) {
	runMCPMode(network, cfg, dataDir)
}
