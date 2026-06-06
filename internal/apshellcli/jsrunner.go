// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/scripting"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

type jsRunnerListenFunc func(network, address string) (net.Listener, error)

// runJSScriptMode runs a JavaScript script file.
func runJSScriptMode(network string, config config.Config, dataDir string, scriptPath string) {
	// Initialize Engine
	eng, err := engine.NewInitializedEngine(network, &config, dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to initialize engine: %v\n", err)
		os.Exit(1)
	}

	// Auto-connect to Signer via SSH tunnel (best-effort)
	if config.LegacySSH != nil {
		token, _ := tokenfile.LoadApshellTokenFromDataDir(dataDir)
		if token != "" {
			localPort, portErr := jsRunnerFindAvailablePort()
			if portErr == nil {
				target := fmt.Sprintf("%s (ssh:%d, signer:%d)", config.LegacySSH.Host, config.LegacySSH.Port, config.LegacySignerPort)
				_, _ = eng.ConnectWithTunnel(target, config.LegacySSH.Host, config.LegacySSH.Port, localPort, config.LegacySignerPort, token, config.LegacySSH.IdentityFile, config.LegacySSH.KnownHostsPath, nil, nil)
			}
		}
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

	_, err = runner.RunWithContext(context.Background(), string(content))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Script error: %v\n", err)
		os.Exit(1)
	}
}

// runJSExpression runs a single JavaScript expression.
func runJSExpression(network string, config config.Config, dataDir string, expr string) {
	// Initialize Engine
	eng, err := engine.NewInitializedEngine(network, &config, dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to initialize engine: %v\n", err)
		os.Exit(1)
	}

	// Auto-connect to Signer via SSH tunnel (best-effort)
	if config.LegacySSH != nil {
		token, _ := tokenfile.LoadApshellTokenFromDataDir(dataDir)
		if token != "" {
			localPort, portErr := jsRunnerFindAvailablePort()
			if portErr == nil {
				target := fmt.Sprintf("%s (ssh:%d, signer:%d)", config.LegacySSH.Host, config.LegacySSH.Port, config.LegacySignerPort)
				_, _ = eng.ConnectWithTunnel(target, config.LegacySSH.Host, config.LegacySSH.Port, localPort, config.LegacySignerPort, token, config.LegacySSH.IdentityFile, config.LegacySSH.KnownHostsPath, nil, nil)
			}
		}
	}

	// Create runner and execute
	runner := scripting.NewGojaRunner(eng)
	runner.SetOutput(func(msg string) {
		fmt.Println(msg)
	})

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

// jsRunnerFindAvailablePort finds an available local port for the SSH tunnel.
func jsRunnerFindAvailablePort() (int, error) {
	return jsRunnerFindAvailablePortWith(net.Listen)
}

func jsRunnerFindAvailablePortWith(listen jsRunnerListenFunc) (int, error) {
	listener, err := listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = listener.Close() }()
	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port, nil
}
