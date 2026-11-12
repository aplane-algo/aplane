// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/appresult"
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

// ExecutePlugin executes a plugin command for JS plugin(), including signing
// and submitting any transactions and following the plugin's continuations.
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

	// The REPL's loop reviews and submits each step's transactions and follows
	// continuations, so plugin() returns only after the last step.
	pr := &PluginResult{Plugin: appresult.Plugin{Plugin: plugin.Manifest.Name}}
	runErr := processPluginResultStructured(p.repl, pr, result, lsigArgs, plugin)
	for _, step := range pr.humanSteps {
		p.repl.renderSubmissionOutput(step.Output)
		p.repl.renderWarnings(step.Warnings)
	}
	return jsPluginOutcome(pr, runErr)
}

// jsPluginOutcome is plugin()'s answer for a finished run. Before anything is
// submitted, a cancel or the plugin's own failure is a {success: false}
// result and other errors are errors. Once a step has submitted transactions,
// a later step that fails, is cancelled or reports failure leaves the workflow
// half done, so that is an error naming what was submitted, never a result a
// script could read as success or as nothing having happened. A completed run
// returns the last step's message, data and presentation, with apshell's
// record of every submitted transaction ID in data.txids and, for more than one
// step, each step's message and IDs in data.steps.
func jsPluginOutcome(pr *PluginResult, runErr error) (bool, string, interface{}, interface{}, error) {
	submitted := pr.submittedTxIDs()
	if len(submitted) == 0 {
		switch {
		case errors.Is(runErr, errPluginTransactionCancelled):
			return false, "Transaction cancelled by user", nil, nil, nil
		case runErr != nil:
			return false, "", nil, nil, runErr
		}
		return pr.Success, pr.Message, pr.Data, pr.Presentation, nil
	}
	if runErr == nil && !pr.Success {
		runErr = errors.New("plugin reported failure")
		if pr.Message != "" {
			runErr = fmt.Errorf("plugin reported failure: %s", pr.Message)
		}
	}
	if runErr != nil {
		return false, "", nil, nil, fmt.Errorf("%w; earlier steps already submitted transaction(s) %s", runErr, strings.Join(submitted, ", "))
	}

	data := map[string]interface{}{}
	if dataMap, ok := appresult.FilterPluginData(pr.Data).(map[string]interface{}); ok {
		for k, v := range dataMap {
			data[k] = v
		}
	}
	// apshell's record of what it submitted, not a value the plugin chose.
	data["txids"] = submitted
	if len(pr.Steps) > 0 {
		data["steps"] = pr.Steps
	}
	return true, pr.Message, data, pr.Presentation, nil
}
