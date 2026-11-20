// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/scripting"
)

// RunJSScriptMode runs a JavaScript script file.
func RunJSScriptMode(network string, cfg config.Config, dataDir string, scriptPath string) {
	// Initialize Engine
	eng := engine.NewInitializedEngine(network, &cfg, dataDir)

	// Read script from file or stdin
	var content []byte
	var err error
	if scriptPath == "-" {
		content, err = io.ReadAll(os.Stdin)
	} else {
		content, err = os.ReadFile(scriptPath)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to read script: %v\n", err)
		os.Exit(1)
	}

	// Create runner and execute
	runner := standaloneScriptRunner(eng, cfg, dataDir)

	_, err = runner.RunWithContext(context.Background(), string(content))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Script error: %v\n", err)
		os.Exit(1)
	}
}

// RunJSExpression runs a single JavaScript expression.
func RunJSExpression(network string, cfg config.Config, dataDir string, expr string) {
	// Initialize Engine
	eng := engine.NewInitializedEngine(network, &cfg, dataDir)

	// Create runner and execute
	runner := standaloneScriptRunner(eng, cfg, dataDir)

	result, err := runner.RunWithContext(context.Background(), expr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Print result if not empty
	if !result.IsEmpty {
		fmt.Println(result.Value)
	}
}

// standaloneScriptRunner builds the runner for a script run outside the
// REPL. The app builds it, so the script has what the shell's own runner
// has, sweep() included; it has no plugins.
func standaloneScriptRunner(eng *engine.Engine, cfg config.Config, dataDir string) *scripting.GojaRunner {
	return apshellapp.New(eng, cfg, dataDir).Scripts.EnsureRunner(func(msg string) {
		fmt.Println(msg)
	}, nil)
}
