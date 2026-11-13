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
	return jsPluginOutcome(pr, runErr, p.repl.app().IsSimulateEnabled())
}

// jsPluginOutcome is plugin()'s answer for a finished run. A run that produced
// no transaction IDs is answered as a single plugin command is: a cancel or the
// plugin's own failure is a {success: false} result, other errors are errors.
// Once the run has produced transaction IDs, from the steps it submitted and
// from a failing step whose submission returned IDs with its error, a step that
// fails, is cancelled or reports failure leaves the workflow half done, so that
// is an error that lists them and says to look them up before running the
// plugin again. The list does not say which of them confirmed: the step
// output does for the steps that completed, and what became of a failing
// step's transactions is not reported. In simulate mode the listed IDs were simulated, not sent, and
// a failed simulation's own IDs are not listed. A completed run returns the
// last step's message, data and presentation, with every transaction ID it
// submitted (simulated, in simulate mode) in data.txids and, for more than one
// such step, each step's message and IDs in data.steps. A plugin's data never
// carries localSigners to the script, in any outcome, and data the plugin
// returned as an object stays an object, empty if localSigners was all it held.
func jsPluginOutcome(pr *PluginResult, runErr error, simulated bool) (bool, string, interface{}, interface{}, error) {
	data := appresult.StripShellOnlyPluginData(pr.Data)
	ids := append([]string(nil), pr.TxIDs...)
	for _, step := range pr.Steps {
		ids = append(ids, step.TxIDs...)
	}
	if !simulated {
		ids = append(ids, pr.failedStepTxIDs...)
	}
	if len(ids) == 0 {
		switch {
		case errors.Is(runErr, errPluginTransactionCancelled):
			return false, "Transaction cancelled by user", nil, nil, nil
		case runErr != nil:
			return false, "", nil, nil, runErr
		}
		return pr.Success, pr.Message, data, pr.Presentation, nil
	}
	if runErr == nil && !pr.Success {
		runErr = errors.New("plugin reported failure")
		if pr.Message != "" {
			runErr = fmt.Errorf("plugin reported failure: %s", pr.Message)
		}
	}
	if runErr != nil {
		if simulated {
			return false, "", nil, nil, fmt.Errorf("%w; this run simulated transaction(s) %s, which were not sent", runErr, strings.Join(ids, ", "))
		}
		return false, "", nil, nil, fmt.Errorf("%w; this run produced transaction(s) %s: look them up before running it again", runErr, strings.Join(ids, ", "))
	}

	result := map[string]interface{}{}
	if dataMap, ok := data.(map[string]interface{}); ok {
		for k, v := range dataMap {
			result[k] = v
		}
	}
	// apshell's record of what it submitted, not a value the plugin chose.
	result["txids"] = ids
	if len(pr.Steps) > 0 {
		result["steps"] = pr.Steps
	}
	return true, pr.Message, result, pr.Presentation, nil
}
