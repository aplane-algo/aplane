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
)

// runJSScriptMode runs a JavaScript script file.
func runJSScriptMode(network string, cfg config.Config, dataDir string, scriptPath string) {
	// Initialize Engine
	eng, err := engine.NewInitializedEngine(network, &cfg, dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to initialize engine: %v\n", err)
		os.Exit(1)
	}

	// Read script from file or stdin
	var content []byte
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
	// The app builds the runner, so the script has what the shell's own
	// runner has, sweep() included.
	runner := apshellapp.New(eng, cfg, dataDir).Scripts.EnsureRunner(func(msg string) {
		fmt.Println(msg)
	}, nil)

	_, err = runner.RunWithContext(context.Background(), string(content))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Script error: %v\n", err)
		os.Exit(1)
	}
}

// runJSExpression runs a single JavaScript expression.
func runJSExpression(network string, cfg config.Config, dataDir string, expr string) {
	// Initialize Engine
	eng, err := engine.NewInitializedEngine(network, &cfg, dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to initialize engine: %v\n", err)
		os.Exit(1)
	}

	// Create runner and execute
	// The app builds the runner, so the script has what the shell's own
	// runner has, sweep() included.
	runner := apshellapp.New(eng, cfg, dataDir).Scripts.EnsureRunner(func(msg string) {
		fmt.Println(msg)
	}, nil)

	result, err := runner.RunWithContext(context.Background(), expr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Print result if not empty
	if !result.IsEmpty {
		switch v := result.Value.(type) {
		case map[string]interface{}, []interface{}:
			fmt.Printf("%v\n", v)
		default:
			fmt.Println(result.Value)
		}
	}
}
