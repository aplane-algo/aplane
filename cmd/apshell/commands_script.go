// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

// Scripting, AI, and plugin execution commands

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/ai"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/scripting"
	"github.com/aplane-algo/aplane/internal/signing"

	"github.com/chzyer/readline"
)

// cmdJS executes JavaScript code in the REPL.
// Supports: js <file.js>, js { code }, js <inline>, and multi-line mode.
func (r *REPLState) cmdJS(args []string, ctxRaw interface{}) error {
	var code string

	// Get raw args from context (preserves quotes that ParseCommand strips)
	ctx, _ := ctxRaw.(*command.Context)
	rawArgs := ""
	if ctx != nil {
		rawArgs = ctx.RawArgs
	}

	if len(args) == 0 {
		// Multi-line mode: read lines until blank line
		fmt.Println("Enter JavaScript code (blank line to execute, Ctrl+C to cancel):")

		var lines []string
		if r.LineReader != nil {
			if r.SetPrompt != nil {
				r.SetPrompt("")
			}
			for {
				line, err := r.LineReader()
				if err != nil {
					if errors.Is(err, readline.ErrInterrupt) {
						fmt.Println("\nCancelled.")
						return nil
					}
					if errors.Is(err, io.EOF) {
						break
					}
					return err
				}
				if line == "" {
					break
				}
				lines = append(lines, line)
			}
		} else {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := scanner.Text()
				if line == "" {
					break
				}
				lines = append(lines, line)
			}
			if err := scanner.Err(); err != nil {
				return err
			}
		}
		if len(lines) == 0 {
			return nil
		}
		code = strings.Join(lines, "\n")
	} else if strings.HasPrefix(rawArgs, "{") {
		// Brace-delimited mode: js { code here }
		// Use rawArgs to preserve quotes inside the braces
		inner := strings.TrimPrefix(rawArgs, "{")
		inner = strings.TrimSpace(inner)

		if strings.HasSuffix(inner, "}") {
			code = strings.TrimSuffix(inner, "}")
			code = strings.TrimSpace(code)
		} else {
			// Read more lines until we find closing brace
			lines := []string{inner}
			if r.LineReader != nil {
				if r.SetPrompt != nil {
					r.SetPrompt("")
				}
				for {
					line, err := r.LineReader()
					if err != nil {
						if errors.Is(err, readline.ErrInterrupt) {
							fmt.Println("\nCancelled.")
							return nil
						}
						if errors.Is(err, io.EOF) {
							break
						}
						return err
					}
					if strings.TrimSpace(line) == "}" {
						break
					}
					lines = append(lines, line)
				}
			} else {
				scanner := bufio.NewScanner(os.Stdin)
				for scanner.Scan() {
					line := scanner.Text()
					if strings.TrimSpace(line) == "}" {
						break
					}
					lines = append(lines, line)
				}
				if err := scanner.Err(); err != nil {
					return err
				}
			}
			code = strings.Join(lines, "\n")
		}
	} else if strings.HasSuffix(args[0], ".js") {
		// File mode: js script.js
		scriptPath := args[0]
		content, err := os.ReadFile(scriptPath)
		if err != nil {
			return fmt.Errorf("failed to read script: %w", err)
		}
		code = string(content)
	} else {
		// Inline mode: js <code>
		// Use rawArgs to preserve quotes
		if rawArgs != "" {
			code = rawArgs
		} else {
			code = strings.Join(args, " ")
		}
	}

	// Initialize JS runner if needed (persistent for state preservation)
	if r.JSRunner == nil {
		runner := scripting.NewGojaRunner(r.Engine)
		runner.SetOutput(func(msg string) {
			fmt.Println(msg)
		})
		// Enable plugin() function if PluginManager is available
		if r.PluginManager != nil {
			runner.SetPluginExecutor(&PluginExecutorAdapter{repl: r})
		}
		r.JSRunner = runner
	}

	// Track last executed script for jssave
	r.LastScript = code
	if len(args) > 0 && strings.HasSuffix(args[0], ".js") {
		r.LastScriptSource = "file:" + args[0]
	} else {
		r.LastScriptSource = "js"
	}

	// Run the code
	result, err := r.JSRunner.Run(code)
	if err != nil {
		return err
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

	return nil
}

// runShellCommand executes a shell command (used by ! prefix).
func (r *REPLState) runShellCommand(cmdStr string) error {
	if cmdStr == "" {
		return nil
	}

	// Execute via sh -c to support pipes, redirects, etc.
	cmd := exec.Command("sh", "-c", cmdStr)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	err := cmd.Run()
	if err != nil {
		// Don't treat non-zero exit as error, just show it happened
		if exitErr, ok := err.(*exec.ExitError); ok {
			fmt.Printf("(exit %d)\n", exitErr.ExitCode())
			return nil
		}
		return fmt.Errorf("failed to execute command: %w", err)
	}

	return nil
}

// cmdAI generates and executes JavaScript code using an AI provider.
func (r *REPLState) cmdAI(args []string, _ interface{}) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ai <prompt>")
	}

	prompt := strings.Join(args, " ")

	// Create AI provider (auto-detects from environment, uses model from config if set)
	provider, err := ai.NewProvider(ai.Config{Model: r.Config.AIModel})
	if err != nil {
		return err
	}

	// Discover plugins and add to AI context
	adapter := &PluginExecutorAdapter{repl: r}
	if plugins := adapter.GetPluginInfo(); len(plugins) > 0 {
		provider.SetPlugins(plugins)
	}
	if functions := adapter.GetFunctionInfo(); len(functions) > 0 {
		provider.SetFunctions(functions)
	}

	fmt.Printf("Generating code via %s...\n", provider.Name())

	// Generate code
	code, err := provider.GenerateCode(prompt)
	if err != nil {
		return fmt.Errorf("failed to generate code: %w", err)
	}

	// Track in LastScript immediately (available for jssave even if user declines)
	r.LastScript = code
	r.LastScriptSource = "ai"

	// Show generated code
	fmt.Println("\n--- Generated Code ---")
	fmt.Println(code)
	fmt.Println("----------------------")

	// Ask for confirmation
	fmt.Print("\nExecute? [y/N]: ")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return nil
	}
	response := strings.ToLower(strings.TrimSpace(scanner.Text()))
	if response != "y" && response != "yes" {
		fmt.Println("Cancelled (use 'jssave <path>' to save the generated code)")
		return nil
	}

	// Execute the code
	if r.JSRunner == nil {
		runner := scripting.NewGojaRunner(r.Engine)
		runner.SetOutput(func(msg string) {
			fmt.Println(msg)
		})
		// Enable plugin() function if PluginManager is available
		if r.PluginManager != nil {
			runner.SetPluginExecutor(&PluginExecutorAdapter{repl: r})
		}
		r.JSRunner = runner
	}

	// Wrap code in an IIFE to avoid goja global scope issues with property access
	// on objects returned from native functions
	wrappedCode := "(function() {\n" + code + "\n})();"
	_, err = r.JSRunner.Run(wrappedCode)
	return err
}

// cmdJSSave saves the last executed JavaScript to a file
func (r *REPLState) cmdJSSave(args []string, _ interface{}) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: jssave <path>")
	}
	filePath := args[0]

	if r.LastScript == "" {
		return fmt.Errorf("no script to save. Execute JavaScript with 'js' or 'ai' first")
	}

	// Add .js extension if not present
	if !strings.HasSuffix(filePath, ".js") {
		filePath = filePath + ".js"
	}

	// Create parent directory if needed
	dir := filepath.Dir(filePath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	// Check if file already exists
	if _, err := os.Stat(filePath); err == nil {
		fmt.Printf("File '%s' already exists. Overwrite? [y/N]: ", filePath)
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			return nil
		}
		response := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if response != "y" && response != "yes" {
			fmt.Println("Cancelled")
			return nil
		}
	}

	// Write the script
	if err := os.WriteFile(filePath, []byte(r.LastScript), 0640); err != nil {
		return fmt.Errorf("failed to write script: %w", err)
	}

	fmt.Printf("Saved to %s (%d bytes)\n", filePath, len(r.LastScript))
	return nil
}

// PluginExecutorAdapter adapts REPLState to the scripting.PluginExecutor interface.
// This allows the JS API to execute external plugins.
type PluginExecutorAdapter struct {
	repl *REPLState
}

// ListPluginCommands returns all available plugin command names for dynamic registration.
func (p *PluginExecutorAdapter) ListPluginCommands() []string {
	if p.repl.PluginManager == nil {
		return nil
	}
	commands, err := p.repl.PluginManager.ListCommands()
	if err != nil {
		return nil
	}
	return commands
}

// GetPluginInfo returns plugin info for AI prompt generation.
func (p *PluginExecutorAdapter) GetPluginInfo() []ai.PluginInfo {
	if p.repl.PluginManager == nil {
		return nil
	}
	plugins, err := p.repl.PluginManager.DiscoverPluginsCached()
	if err != nil {
		return nil
	}

	var result []ai.PluginInfo
	for _, plugin := range plugins {
		for _, cmd := range plugin.Manifest.Commands {
			result = append(result, ai.PluginInfo{
				CommandName: cmd.Name,
				Description: cmd.Description,
				Usage:       cmd.Usage,
				Examples:    cmd.Examples,
				Returns:     cmd.Returns,
				Category:    cmd.Category,
				ArgSpecs:    cmd.ArgSpecs,
			})
		}
	}
	return result
}

// GetFunctionInfo returns typed function info for AI prompt generation.
func (p *PluginExecutorAdapter) GetFunctionInfo() []ai.FunctionInfo {
	if p.repl.PluginManager == nil {
		return nil
	}
	plugins, err := p.repl.PluginManager.DiscoverPluginsCached()
	if err != nil {
		return nil
	}

	var result []ai.FunctionInfo
	for _, plugin := range plugins {
		for _, fn := range plugin.Manifest.Functions {
			params := make([]ai.FunctionParam, len(fn.Params))
			for i, fp := range fn.Params {
				params[i] = ai.FunctionParam{
					Name:        fp.Name,
					Type:        fp.Type,
					Description: fp.Description,
				}
			}
			result = append(result, ai.FunctionInfo{
				Name:        fn.Name,
				Description: fn.Description,
				Params:      params,
				Returns:     fn.Returns,
			})
		}
	}
	return result
}

// ExecutePlugin executes a plugin command, including signing and submitting any transactions.
func (p *PluginExecutorAdapter) ExecutePlugin(pluginName string, args []string) (bool, string, interface{}, error) {
	if p.repl.PluginManager == nil {
		return false, "", nil, fmt.Errorf("plugin manager not initialized")
	}

	// Find plugin using cached discovery - first try by command name, then by manifest name
	plugin, err := p.repl.PluginManager.FindByCommand(pluginName)
	if err != nil {
		// Try finding by manifest name (for typed plugin functions)
		plugin, err = p.repl.PluginManager.FindByName(pluginName)
		if err != nil {
			return false, "", nil, fmt.Errorf("plugin or command '%s' not found", pluginName)
		}
	}

	// Check if plugin supports current network (uses engine's network which may differ from manager's)
	if !plugin.Manifest.SupportsNetwork(p.repl.Engine.Network) {
		return false, "", nil, fmt.Errorf("plugin '%s' does not support network '%s'", plugin.Manifest.Name, p.repl.Engine.Network)
	}

	// Build execution context
	assetMap := make(map[string]uint64)
	for assetID, asaInfo := range p.repl.Engine.AsaCache.Assets {
		if asaInfo.Name != "" {
			assetMap[asaInfo.Name] = assetID
		}
		if asaInfo.UnitName != "" {
			assetMap[asaInfo.UnitName] = assetID
		}
	}

	addressMap := make(map[string]string)
	for alias, address := range p.repl.Engine.AliasCache.Aliases {
		addressMap[alias] = address
	}

	p.repl.Engine.EnsureSignerCache()
	var accounts []string
	for address := range p.repl.Engine.SignerCache.Keys {
		accounts = append(accounts, address)
	}

	context := jsonrpc.Context{
		Network:    p.repl.Engine.Network,
		Accounts:   accounts,
		AssetMap:   assetMap,
		AddressMap: addressMap,
	}

	// Normalize address arguments based on ArgSpecs
	normalizedArgs := args
	if manifestCmd := plugin.Manifest.FindCommand(pluginName); manifestCmd != nil && len(manifestCmd.ArgSpecs) > 0 {
		normalizedArgs = normalizeAddressArgs(manifestCmd.ArgSpecs, args)
	}

	// Execute the plugin command
	result, err := p.repl.PluginManager.ExecuteCommand(plugin.Manifest.Name, pluginName, normalizedArgs, context)
	if err != nil {
		return false, "", nil, fmt.Errorf("plugin execution failed: %w", err)
	}

	// If no transactions, return early
	if len(result.Transactions) == 0 {
		return result.Success, result.Message, result.Data, nil
	}

	// Handle transactions - check if signer is connected
	if p.repl.Engine.SignerClient == nil {
		return false, "", nil, fmt.Errorf("not connected to signer - use connect() first to sign transactions")
	}

	// Process transaction intents
	txns, _, err := p.repl.processTransactionIntents(result.Transactions)
	if err != nil {
		return false, "", nil, fmt.Errorf("failed to process transactions: %w", err)
	}

	// Check for local signer data
	localSigners, err := parseLocalSigners(result.Data)
	if err != nil {
		return false, "", nil, fmt.Errorf("failed to parse local signers: %w", err)
	}

	// Sign and submit
	var txIDs []string
	if len(localSigners) > 0 {
		txIDs, err = p.repl.signAndSubmitWithLocalSigners(txns, localSigners, nil)
	} else {
		// Use /sign endpoint (server handles dummies, fees, grouping)
		txIDs, err = signing.SignAndSubmitViaGroup(
			txns,
			&p.repl.Engine.AuthCache,
			p.repl.Engine.SignerClient,
			p.repl.Engine.AlgodClient,
			signing.SubmitOptions{
				WaitForConfirmation: true,
				Verbose:             p.repl.Engine.Verbose,
				Simulate:            p.repl.Engine.Simulate,
				TxnWriter:           p.repl.Engine.WriteTxnCallback(),
			},
		)
	}
	if err != nil {
		return false, "", nil, fmt.Errorf("failed to sign/submit: %w", err)
	}

	// Build response with txids
	responseData := map[string]interface{}{
		"txids": txIDs,
	}
	// Merge any plugin data (exclude local signer fields)
	if result.Data != nil {
		if dataMap, ok := result.Data.(map[string]interface{}); ok {
			for k, v := range dataMap {
				if k != "localSigners" {
					responseData[k] = v
				}
			}
		}
	}

	return true, result.Message, responseData, nil
}
