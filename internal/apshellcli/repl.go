// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/aplane-algo/aplane/internal/config"

	"github.com/chzyer/readline"
)

func startBasicREPL(state *REPLState) {
	fmt.Println("Running in basic mode (no history/completion)")
	stopPolling := state.startSignerStatusPolling(nil)
	defer stopPolling()
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("%s%s> ", state.app().ConnectionIndicator(), state.app().Network())
		if !scanner.Scan() {
			break
		}
		input := scanner.Text()

		if handled, err := state.handleShellInput(input); handled {
			if err != nil {
				fmt.Printf("Error: %v\n", err)
			}
			continue
		}

		cmd, err := state.parseInputCommand(input)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}
		if cmd.Name == "" {
			continue
		}

		state.runtimeMu.Lock()
		err = state.executeCommand(cmd)
		state.runtimeMu.Unlock()
		if err != nil {
			if err.Error() == "exit" {
				break
			}
			fmt.Printf("Error: %v\n", err)
		}
	}

	shutdownRuntime(state)
}

func startREPL(network string, config config.Config, dataDir string) {
	fmt.Println("apshell - APlane Shell")
	fmt.Println("Type 'help' for available commands or 'quit' to exit")
	fmt.Println("Features: Command history (↑/↓), Tab completion, Ctrl+C to interrupt")

	// Create REPLState with initialized runtime state and app facade.
	state, err := NewREPLState(network, &config, dataDir)
	if err != nil {
		fmt.Printf("Error: failed to initialize application state: %v\n", err)
		os.Exit(1)
	}

	state.Config = config                               // Store config for network restrictions
	state.CommandRegistry = state.initCommandRegistry() // Initialize command registry with plugin support

	if err := initPluginRuntime(state); err != nil {
		fmt.Printf("Error: failed to initialize plugins: %v\n", err)
		os.Exit(1)
	}
	printInteractiveStartupConnectionStatus(state)

	rl, err := readline.NewEx(state.newReadlineConfig())
	if err != nil {
		fmt.Printf("Failed to create readline instance, falling back to basic input: %v\n", err)
		startBasicREPL(state)
		return
	}
	defer func() {
		_ = rl.Close() // Best-effort close, errors during shutdown not critical
	}()

	state.bindInteractiveIO(rl)
	stopPolling := state.startSignerStatusPolling(func() {
		state.refreshCompleter(rl)
	})
	defer stopPolling()

	// sigCh intercepts SIGINT during command execution so Ctrl-C
	// cancels the in-flight operation instead of killing the process.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	for {
		rl.SetPrompt(state.promptString())

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

		if handled, err := state.handleShellInput(line); handled {
			if err != nil {
				fmt.Printf("Error: %v\n", err)
			}
			continue
		}

		cmd, err := state.parseInputCommand(line)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}
		if cmd.Name == "" {
			continue
		}

		if cmd.Name == "network" && len(cmd.Args) == 1 {
			err := state.executeCommandWithInterrupt(cmd, sigCh)
			if err != nil {
				if err.Error() == "exit" {
					break
				}
				fmt.Printf("Error: %v\n", err)
			}
			state.refreshCompleter(rl)
			continue
		}

		err = state.executeCommandWithInterrupt(cmd, sigCh)
		if err != nil {
			if err.Error() == "exit" {
				break
			}
			fmt.Printf("Error: %v\n", err)
		}
	}

	shutdownRuntime(state)
}

// runScriptMode executes a script file and exits
func runScriptMode(network string, config config.Config, dataDir string, scriptPath string) {
	// Create REPLState with initialized runtime state and app facade.
	state, err := NewREPLState(network, &config, dataDir)
	if err != nil {
		fmt.Printf("Error: failed to initialize application state: %v\n", err)
		os.Exit(1)
	}

	state.Config = config    // Store config for network restrictions
	state.AutoConfirm = true // Non-interactive: skip confirmation prompts
	state.CommandRegistry = state.initCommandRegistry()

	if err := initPluginRuntime(state); err != nil {
		fmt.Printf("Error: failed to initialize plugins: %v\n", err)
		os.Exit(1)
	}
	_ = attemptStartupConnection(state)

	// Run the script
	err = state.runScript([]string{scriptPath})

	shutdownRuntime(state)

	if err != nil && err.Error() != "exit" {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
