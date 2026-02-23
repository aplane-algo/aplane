// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/cmd/apshell/internal/repl"
	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/plugin/manager"
	"github.com/aplane-algo/aplane/internal/util"

	"github.com/chzyer/readline"
)

func startBasicREPL(state *REPLState) {
	fmt.Println("Running in basic mode (no history/completion)")
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("%s%s> ", state.GetConnectionIndicator(), state.Engine.Network)
		if !scanner.Scan() {
			break
		}
		input := scanner.Text()

		// Handle ! prefix for shell commands (e.g., !ls)
		trimmedInput := strings.TrimSpace(input)
		if strings.HasPrefix(trimmedInput, "!") {
			if err := state.runShellCommand(trimmedInput[1:]); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
			continue
		}

		cmdName, cmdArgs := algo.ParseCommand(input)
		if cmdName == "" {
			continue
		}
		cmd := Command{Name: cmdName, Args: cmdArgs}

		// For js command, preserve raw args (quotes get stripped by ParseCommand)
		if cmdName == "js" {
			if len(trimmedInput) > 2 { // "js" + at least one char
				cmd.RawArgs = strings.TrimSpace(trimmedInput[2:])
			}
		}

		// Quick connection check for localhost (SSH has its own callback)
		state.checkLocalhostConnection()
		err := state.executeCommand(cmd)
		if err != nil {
			if err.Error() == "exit" {
				break
			}
			fmt.Printf("Error: %v\n", err)
		}
	}

	// Cleanup: Close SSH tunnel if still open
	_ = state.disconnectTunnel() // Best-effort cleanup on exit

	// Cleanup: Stop all external plugins
	if state.PluginManager != nil {
		state.PluginManager.StopAll()
	}
}

func startREPL(network string, config util.Config) {
	fmt.Println("apshell - aPlane Shell")
	fmt.Println("Type 'help' for available commands or 'quit' to exit")
	fmt.Println("Features: Command history (↑/↓), Tab completion, Ctrl+C to interrupt")

	// Create REPLState with initialized Engine (single source of truth)
	state, err := NewREPLState(network, &config)
	if err != nil {
		fmt.Printf("Error: failed to initialize application state: %v\n", err)
		os.Exit(1)
	}

	state.Config = config                               // Store config for network restrictions
	state.CommandRegistry = state.initCommandRegistry() // Initialize command registry with plugin support

	// Initialize plugin manager for external plugins
	state.PluginManager = manager.NewManager()
	// Set plugin manager config with network API server
	var apiServer string
	switch state.Engine.Network {
	case "mainnet":
		apiServer = "https://mainnet-api.algonode.cloud"
	case "testnet":
		apiServer = "https://testnet-api.algonode.cloud"
	case "betanet":
		apiServer = "https://betanet-api.algonode.cloud"
	}
	state.PluginManager.SetConfig(state.Engine.Network, apiServer, "", "")

	// Auto-connect to Signer if token exists
	token, _ := util.LoadApshellToken()
	if token == "" {
		// No token - print helpful message with both options
		fmt.Println("Not connected to Signer (no token configured)")
		fmt.Printf("  Run 'request-token' to obtain a token, or copy aplane.token to %s\n", getTokenPathDescription())
	} else if config.SSH != nil && config.SSH.Host != "localhost" && config.SSH.Host != "127.0.0.1" {
		// Remote connection via SSH tunnel (SSH config with non-localhost host)
		fmt.Printf("Verifying Signer via SSH: %s (SSH port: %d, signer port: %d)\n",
			config.SSH.Host, config.SSH.Port, config.SignerPort)
		err = state.connectTunnelWithKey(config.SSH.Host, config.SSH.Port, config.SignerPort)
		if err != nil {
			fmt.Printf("Warning: Signer verification failed: %v\n", err)
			fmt.Println("Signer not available (run 'connect' to retry)")
		}
	} else {
		// Direct connection to localhost (SSH config with localhost host still uses direct,
		// but SSH remains available for token provisioning via 'request-token')
		fmt.Printf("Verifying Signer: localhost:%d\n", config.SignerPort)
		hostPort := fmt.Sprintf("localhost:%d", config.SignerPort)
		err = state.connectDirect(hostPort)
		if err != nil {
			fmt.Printf("Warning: Signer verification failed: %v\n", err)
			fmt.Println("Signer not available (run 'connect' to retry)")
		}
	}

	// Discover external plugins for autocomplete
	externalPlugins, _ := state.PluginManager.DiscoverPlugins()

	homeDir, _ := os.UserHomeDir()
	historyFile := filepath.Join(homeDir, ".apshell_history")

	rlConfig := &readline.Config{
		Prompt:            fmt.Sprintf("\033[32m%s%s%s>\033[0m ", state.GetConnectionIndicator(), state.Engine.Network, state.GetModeFlags()),
		HistoryFile:       historyFile,
		HistoryLimit:      1000,
		AutoComplete:      repl.CreateDynamicCompleter(&state.Engine.AliasCache, &state.Engine.AsaCache, &state.Engine.SetCache, &state.Engine.SignerCache, externalPlugins),
		InterruptPrompt:   "^C",
		EOFPrompt:         "exit",
		HistorySearchFold: true,
	}

	rl, err := readline.NewEx(rlConfig)
	if err != nil {
		fmt.Printf("Failed to create readline instance, falling back to basic input: %v\n", err)
		startBasicREPL(state)
		return
	}
	defer func() {
		_ = rl.Close() // Best-effort close, errors during shutdown not critical
	}()

	// Set up LineReader and SetPrompt for multi-line input (e.g., keyreg paste mode, js multi-line)
	state.LineReader = func() (string, error) {
		return rl.Readline()
	}
	state.SetPrompt = func(p string) {
		rl.SetPrompt(p)
	}

	for {
		rl.SetPrompt(fmt.Sprintf("\033[32m%s%s%s>\033[0m ", state.GetConnectionIndicator(), state.Engine.Network, state.GetModeFlags()))

		line, err := rl.Readline()
		if err != nil {
			if errors.Is(err, readline.ErrInterrupt) {
				if len(line) == 0 {
					fmt.Println("Use 'quit' or 'exit' to exit")
				}
				continue
			}
			if errors.Is(err, io.EOF) {
				fmt.Println("\nGoodbye!")
				break
			}
			fmt.Printf("Error reading input: %v\n", err)
			continue
		}

		// Handle ! prefix for shell commands (e.g., !ls)
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "!") {
			if err := state.runShellCommand(trimmedLine[1:]); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
			continue
		}

		// Macro expansion has been removed for safety
		cmdName, cmdArgs := algo.ParseCommand(line)
		if cmdName == "" {
			continue
		}
		cmd := Command{Name: cmdName, Args: cmdArgs}

		// For js command, preserve raw args (quotes get stripped by ParseCommand)
		if cmdName == "js" {
			if len(trimmedLine) > 2 { // "js" + at least one char
				cmd.RawArgs = strings.TrimSpace(trimmedLine[2:])
			}
		}

		// Quick connection check for localhost (SSH has its own callback)
		state.checkLocalhostConnection()

		if cmd.Name == "network" && len(cmd.Args) == 1 {
			err := state.executeCommand(cmd)
			if err != nil {
				if err.Error() == "exit" {
					break
				}
				fmt.Printf("Error: %v\n", err)
			}
			// Re-discover plugins after network change (they may have different network support)
			updatedPlugins, _ := state.PluginManager.DiscoverPlugins()
			rl.Config.AutoComplete = repl.CreateDynamicCompleter(&state.Engine.AliasCache, &state.Engine.AsaCache, &state.Engine.SetCache, &state.Engine.SignerCache, updatedPlugins)
			continue
		}

		err = state.executeCommand(cmd)
		if err != nil {
			if err.Error() == "exit" {
				break
			}
			fmt.Printf("Error: %v\n", err)
		}
	}

	// Cleanup: Close SSH tunnel if still open
	_ = state.disconnectTunnel() // Best-effort cleanup on exit

	// Cleanup: Stop all external plugins
	if state.PluginManager != nil {
		state.PluginManager.StopAll()
	}
}

// runScriptMode executes a script file and exits
func runScriptMode(network string, config util.Config, scriptPath string) {
	// Create REPLState with initialized Engine
	state, err := NewREPLState(network, &config)
	if err != nil {
		fmt.Printf("Error: failed to initialize application state: %v\n", err)
		os.Exit(1)
	}

	state.Config = config // Store config for network restrictions
	state.CommandRegistry = state.initCommandRegistry()

	// Initialize plugin manager for external plugins
	state.PluginManager = manager.NewManager()
	var apiServer string
	switch state.Engine.Network {
	case "mainnet":
		apiServer = "https://mainnet-api.algonode.cloud"
	case "testnet":
		apiServer = "https://testnet-api.algonode.cloud"
	case "betanet":
		apiServer = "https://betanet-api.algonode.cloud"
	}
	state.PluginManager.SetConfig(state.Engine.Network, apiServer, "", "")

	// Auto-connect to signer (best-effort, script may not need connection)
	if token, _ := util.LoadApshellToken(); token != "" {
		if config.SSH != nil {
			_ = state.connectTunnelWithKey(config.SSH.Host, config.SSH.Port, config.SignerPort)
		} else {
			hostPort := fmt.Sprintf("localhost:%d", config.SignerPort)
			_ = state.connectDirect(hostPort)
		}
	}

	// Run the script
	err = state.runScript([]string{scriptPath})

	// Cleanup
	_ = state.disconnectTunnel()
	if state.PluginManager != nil {
		state.PluginManager.StopAll()
	}

	if err != nil && err.Error() != "exit" {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
