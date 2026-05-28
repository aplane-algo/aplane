// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	pluginmanager "github.com/aplane-algo/aplane/internal/plugin/manager"
)

// PluginExecutorAdapter adapts REPLState to the scripting.PluginExecutor interface.
// This allows the JS API to execute external plugins.
type PluginExecutorAdapter struct {
	repl *REPLState
}

func (r *REPLState) ensureJSRunner() {
	if r.Scripts.Runner != nil {
		return
	}

	var pluginExecutor *PluginExecutorAdapter
	if r.app().Plugins != nil {
		pluginExecutor = &PluginExecutorAdapter{repl: r}
	}
	r.Scripts.Runner = r.app().Scripts.EnsureRunner(func(msg string) {
		r.println(msg)
	}, pluginExecutor)
}

// ListPluginCommands returns all available plugin command names for dynamic registration.
func (p *PluginExecutorAdapter) ListPluginCommands() []string {
	if p.repl.app().Plugins == nil {
		return nil
	}
	commands, err := p.repl.app().Plugins.ListCommands()
	if err != nil {
		return nil
	}
	return commands
}

// ExecutePlugin executes a plugin command, including signing and submitting any transactions.
func (p *PluginExecutorAdapter) ExecutePlugin(pluginName string, args []string) (bool, string, interface{}, interface{}, error) {
	if p.repl.app().Plugins == nil {
		return false, "", nil, nil, fmt.Errorf("plugin manager not initialized")
	}

	// Find plugin using cached discovery - first try by command name, then by manifest name
	plugin, err := p.repl.app().Plugins.FindByCommand(pluginName)
	if err != nil {
		if errors.Is(err, pluginmanager.ErrNoPluginForCommand) {
			// Try finding by manifest name for typed-function-oriented callers.
			// Execution still routes through plugin command dispatch.
			plugin, err = p.repl.app().Plugins.FindByName(pluginName)
			if err != nil {
				return false, "", nil, nil, fmt.Errorf("plugin or command '%s' not found", pluginName)
			}
		} else {
			return false, "", nil, nil, err
		}
	}

	// Check if plugin supports current network (uses engine's network which may differ from manager's)
	if !p.repl.app().PluginSupportsCurrentNetwork(plugin) {
		return false, "", nil, nil, fmt.Errorf("plugin '%s' does not support network '%s'", plugin.Manifest.Name, p.repl.app().Network())
	}

	context, err := p.repl.app().BuildPluginContext()
	if err != nil {
		return false, "", nil, nil, err
	}

	pluginArgs, lsigArgs, err := extractPluginLsigArgs(args)
	if err != nil {
		return false, "", nil, nil, err
	}
	normalizedArgs := apshellapp.NormalizePluginCommandArgs(plugin, pluginName, pluginArgs)

	// Execute the plugin command
	result, err := p.repl.app().Plugins.ExecuteCommand(plugin.Manifest.Name, pluginName, normalizedArgs, context)
	if err != nil {
		return false, "", nil, nil, fmt.Errorf("plugin execution failed: %w", err)
	}
	if err := apshellapp.ValidatePluginExecuteResult(result); err != nil {
		return false, "", nil, nil, err
	}

	// If no transactions, return early
	if len(result.Transactions) == 0 {
		return result.Success, result.Message, result.Data, result.Presentation, nil
	}

	cancelled, err := reviewPluginTransactions(p.repl, result)
	if err != nil {
		return false, "", nil, nil, err
	}
	if cancelled {
		return false, "Transaction cancelled by user", nil, nil, nil
	}

	// Handle transactions - check if signer is connected
	if !p.repl.app().IsConnected() {
		return false, "", nil, nil, fmt.Errorf("not connected to signer - use connect() first to sign transactions")
	}

	submit, err := p.repl.app().SubmitPluginTransactions(p.repl.commandContext(), result, lsigArgs)
	if err != nil {
		return false, "", nil, nil, fmt.Errorf("failed to sign/submit: %w", err)
	}
	p.repl.renderSubmissionOutput(submit.Output)
	p.repl.renderWarnings(submit.Warnings)

	// Build response with txids
	responseData := map[string]interface{}{
		"txids": submit.TxIDs,
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

	return true, result.Message, responseData, result.Presentation, nil
}
