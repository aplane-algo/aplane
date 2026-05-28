// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
)

// PluginCommandExecution describes one executed plugin command step.
type PluginCommandExecution struct {
	Plugin *discovery.Plugin
	Result *jsonrpc.ExecuteResult
}

func validatePluginResult(result *jsonrpc.ExecuteResult) error {
	if result == nil {
		return fmt.Errorf("plugin returned nil result")
	}
	if !result.Success && len(result.Transactions) > 0 {
		return fmt.Errorf("plugin returned transactions with success=false")
	}
	if !result.Success && result.Continuation != nil {
		return fmt.Errorf("plugin returned continuation with success=false")
	}
	if result.Continuation != nil && result.Continuation.Command == "" {
		return fmt.Errorf("plugin continuation command is required")
	}
	return nil
}

// ValidatePluginExecuteResult validates a plugin execute result using the app-owned rules.
func ValidatePluginExecuteResult(result *jsonrpc.ExecuteResult) error {
	return validatePluginResult(result)
}

func normalizePluginCommandArgs(plugin *discovery.Plugin, commandName string, args []string) []string {
	if plugin == nil {
		return args
	}
	if manifestCmd := plugin.Manifest.FindCommand(commandName); manifestCmd != nil && len(manifestCmd.ArgSpecs) > 0 {
		return normalizePluginAddressArgs(manifestCmd.ArgSpecs, args)
	}
	return args
}

// NormalizePluginCommandArgs normalizes plugin arguments using the app-owned ArgSpec rules.
func NormalizePluginCommandArgs(plugin *discovery.Plugin, commandName string, args []string) []string {
	return normalizePluginCommandArgs(plugin, commandName, args)
}

func normalizePluginAddressArgs(specs []cmdspec.ArgSpec, args []string) []string {
	if len(specs) == 0 || len(args) == 0 {
		return args
	}

	result := make([]string, len(args))
	copy(result, args)

	addrPattern := regexp.MustCompile(`^[A-Za-z2-7]{58}$`)

	currentSpecs := specs
	currentOffset := 0

	for i := 0; i < len(args); i++ {
		specIdx := i - currentOffset
		if specIdx >= len(currentSpecs) {
			break
		}

		spec := currentSpecs[specIdx]

		if len(spec.Branches) > 0 {
			var matchedBranch *cmdspec.ArgBranch
			for _, branch := range spec.Branches {
				if branch.When.Arg < len(args) {
					argValue := args[branch.When.Arg]
					if matched, _ := regexp.MatchString(branch.When.Matches, argValue); matched {
						matchedBranch = &branch
						break
					}
				}
			}

			if matchedBranch != nil {
				currentSpecs = matchedBranch.Specs
				currentOffset = i
				specIdx = 0
				spec = currentSpecs[specIdx]
			} else {
				continue
			}
		}

		if spec.Type == cmdspec.ArgTypeAddress && addrPattern.MatchString(result[i]) {
			result[i] = strings.ToUpper(result[i])
		}
	}

	return result
}

// ExecutePluginCommand resolves and executes a plugin command against the current network context.
func (a *App) ExecutePluginCommand(_ context.Context, commandName string, args []string) (*PluginCommandExecution, error) {
	if a == nil || a.Plugins == nil {
		return nil, fmt.Errorf("plugin manager not initialized")
	}

	plugin, err := a.Plugins.FindByCommand(commandName)
	if err != nil {
		return nil, err
	}
	if !a.PluginSupportsCurrentNetwork(plugin) {
		return nil, fmt.Errorf("plugin '%s' does not support network '%s'", plugin.Manifest.Name, a.Network())
	}

	pluginContext, err := a.BuildPluginContext()
	if err != nil {
		return nil, err
	}

	normalizedArgs := normalizePluginCommandArgs(plugin, commandName, args)
	result, err := a.Plugins.ExecuteCommand(plugin.Manifest.Name, commandName, normalizedArgs, pluginContext)
	if err != nil {
		return nil, err
	}
	if err := validatePluginResult(result); err != nil {
		return nil, err
	}

	return &PluginCommandExecution{
		Plugin: plugin,
		Result: result,
	}, nil
}

// ContinuePluginCommand executes a plugin continuation step in the current runtime context.
func (a *App) ContinuePluginCommand(_ context.Context, plugin *discovery.Plugin, cont *jsonrpc.Continuation) (*jsonrpc.ExecuteResult, error) {
	if a == nil || a.Plugins == nil {
		return nil, fmt.Errorf("plugin manager not initialized")
	}
	if plugin == nil {
		return nil, fmt.Errorf("plugin continuation requires plugin metadata")
	}

	pluginContext, err := a.BuildPluginContext()
	if err != nil {
		return nil, err
	}
	pluginContext.Continuation = cont.Context

	normalizedArgs := normalizePluginCommandArgs(plugin, cont.Command, cont.Args)
	result, err := a.Plugins.ExecuteCommand(plugin.Manifest.Name, cont.Command, normalizedArgs, pluginContext)
	if err != nil {
		return nil, err
	}
	if err := validatePluginResult(result); err != nil {
		return nil, err
	}
	return result, nil
}
