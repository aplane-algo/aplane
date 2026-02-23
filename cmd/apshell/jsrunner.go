// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/scripting"
	"github.com/aplane-algo/aplane/internal/util"
)

// runJSScriptMode runs a JavaScript script file.
func runJSScriptMode(network string, config util.Config, scriptPath string) {
	// Initialize Engine
	eng, err := engine.NewInitializedEngine(network, &config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to initialize engine: %v\n", err)
		os.Exit(1)
	}

	// Auto-connect to Signer (direct connection to localhost only for JS runner)
	// SSH tunnel connections require more state management - use apshell for remote
	if config.SSH == nil {
		hostPort := fmt.Sprintf("localhost:%d", config.SignerPort)
		token, _ := util.LoadApshellToken()
		_, _ = eng.ConnectDirect(hostPort, token) // Best-effort
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
	runner := scripting.NewGojaRunner(eng)
	runner.SetOutput(func(msg string) {
		fmt.Println(msg)
	})

	_, err = runner.Run(string(content))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Script error: %v\n", err)
		os.Exit(1)
	}
}

// runJSExpression runs a single JavaScript expression.
func runJSExpression(network string, config util.Config, expr string) {
	// Initialize Engine
	eng, err := engine.NewInitializedEngine(network, &config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to initialize engine: %v\n", err)
		os.Exit(1)
	}

	// Auto-connect to Signer (direct connection to localhost only)
	if config.SSH == nil {
		hostPort := fmt.Sprintf("localhost:%d", config.SignerPort)
		token, _ := util.LoadApshellToken()
		_, _ = eng.ConnectDirect(hostPort, token) // Best-effort
	}

	// Create runner and execute
	runner := scripting.NewGojaRunner(eng)
	runner.SetOutput(func(msg string) {
		fmt.Println(msg)
	})

	result, err := runner.Run(expr)
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
