// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
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
		normalized, err := normalizePluginAddressArgs(manifestCmd.ArgSpecs, args)
		if err != nil {
			// Normalization only uppercases addresses, so a spec it cannot
			// read is no reason to refuse the command.
			logger().Debug("plugin arg_specs unreadable; the arguments from there on are passed as typed",
				"plugin", plugin.Manifest.Name, "command", commandName, "error", err)
		}
		return normalized
	}
	return args
}

// NormalizePluginCommandArgs normalizes plugin arguments using the app-owned ArgSpec rules.
func NormalizePluginCommandArgs(plugin *discovery.Plugin, commandName string, args []string) []string {
	return normalizePluginCommandArgs(plugin, commandName, args)
}

var pluginAddressArg = regexp.MustCompile(`^[A-Za-z2-7]{58}$`)

// normalizePluginAddressArgs uppercases the arguments the specs declare as
// addresses, reading branches with cmdspec.ArgSpecAt as completion does. At a
// branch it cannot read it stops and returns the reason: that argument and
// those after it stay as typed.
func normalizePluginAddressArgs(specs []cmdspec.ArgSpec, args []string) ([]string, error) {
	result := slices.Clone(args)
	for i := range result {
		spec, err := cmdspec.ArgSpecAt(specs, args, i)
		if err != nil {
			return result, err
		}
		if spec != nil && spec.Type == cmdspec.ArgTypeAddress && pluginAddressArg.MatchString(result[i]) {
			result[i] = strings.ToUpper(result[i])
		}
	}
	return result, nil
}

// logger returns the plugin logger. It is made at each call, because a logger
// kept from package initialization would miss the handler the host installs.
// The component matches plugin discovery's; "plugin" is reserved for what
// plugins themselves print.
func logger() *slog.Logger {
	return slog.With("component", "plugins")
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
