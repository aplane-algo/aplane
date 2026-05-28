// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/addressdisplay"
	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/keytypefmt"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
)

// CompleterDeps exposes the narrow cache/view state needed by the interactive completer.
type CompleterDeps struct {
	AliasCache        *cache.AliasCache
	ASACache          *cache.ASACache
	SetCache          *cache.SetCache
	SignerCache       *cache.SignerCache
	EnsureSignerCache func() error
}

// Network returns the current selected network.
func (a *App) Network() string {
	return a.eng.GetNetwork()
}

// ApplyClientCacheUpdates refreshes in-memory cache snapshots for shared cache files changed by another client.
func (a *App) ApplyClientCacheUpdates() error {
	return a.eng.ApplyClientCacheUpdates()
}

// StopClientCacheWatcher stops passive shared-client-cache watching.
func (a *App) StopClientCacheWatcher() {
	a.eng.StopClientCacheWatcher()
}

// IsConnected reports whether a signer connection is active.
func (a *App) IsConnected() bool {
	return a.eng.IsConnected()
}

// SyncSignerStatus checks signer status and refreshes local signer
// cache state when the signer's keyset revision has changed.
func (a *App) SyncSignerStatus(ctx context.Context) (*engine.SignerStatusSyncResult, error) {
	return a.eng.SyncSignerStatusWithContext(ctx)
}

// HasAlias reports whether the given name exists in the alias cache.
func (a *App) HasAlias(name string) bool {
	return a.eng.HasAlias(name)
}

// IsTunnelConnected reports whether the current signer connection is bound to an SSH tunnel.
func (a *App) IsTunnelConnected() bool {
	return a.eng.IsTunnelConnected()
}

// ExecutionState returns the current shell-relevant runtime state.
func (a *App) ExecutionState() CommandExecutionState {
	return CommandExecutionState{
		Network:       a.Network(),
		IsConnected:   a.IsConnected(),
		IsTunnelBound: a.IsTunnelConnected(),
		WriteMode:     a.eng.GetWriteMode(),
		Simulate:      a.eng.GetSimulate(),
	}
}

// IsSimulateEnabled reports whether simulate mode is currently enabled.
func (a *App) IsSimulateEnabled() bool {
	return a.eng.GetSimulate()
}

// FormatAddress formats an address for display, with optional auth address context.
func (a *App) FormatAddress(address, authAddress string) string {
	return a.eng.FormatAddressWithAuth(address, authAddress)
}

// FormatKeyTypeForDisplay formats the displayed key type using cached signer/native key metadata.
func (a *App) FormatKeyTypeForDisplay(address, keyType string) string {
	nativeType := a.eng.SignerCache.GetKeyType(address)
	if nativeType == "" {
		nativeType = keyType
	}
	return addressdisplay.FormatWithKeyColor(keytypefmt.Display(keyType), nativeType, algorithm.GetDisplayColor)
}

// ResolveAddress resolves one address, alias, or dynamic set reference to a concrete address.
func (a *App) ResolveAddress(input string) (string, error) {
	return a.eng.NewAddressResolver().ResolveSingle(input)
}

// ResolveAddressList resolves one or more address, alias, or dynamic set references.
func (a *App) ResolveAddressList(inputs []string) ([]string, error) {
	return a.eng.NewAddressResolver().ResolveList(inputs)
}

// ResolveAssetMetadata resolves an asset reference against the current network.
func (a *App) ResolveAssetMetadata(ref string) (asa.Metadata, error) {
	return cmdspec.ResolveAssetMetadata(a.Network(), ref, a.eng.ASAResolver())
}

// ConnectionIndicator returns the prompt indicator for disconnected state.
func (a *App) ConnectionIndicator() string {
	if a.IsConnected() {
		return ""
	}
	return "(disc) "
}

// ModeFlags returns the short prompt flags for active shell execution modes.
func (a *App) ModeFlags() string {
	state := a.ExecutionState()
	flags := ""
	if state.Simulate {
		flags += "s"
	}
	if state.WriteMode {
		flags += "w"
	}
	if flags == "" {
		return ""
	}
	return " " + strings.TrimSpace(flags)
}

// BuildPluginContext constructs the plugin execution context from current engine state.
func (a *App) BuildPluginContext() (jsonrpc.Context, error) {
	return a.eng.BuildPluginContext()
}

// PluginSupportsCurrentNetwork reports whether a plugin supports the current app network.
func (a *App) PluginSupportsCurrentNetwork(plugin *discovery.Plugin) bool {
	if plugin == nil {
		return false
	}
	return plugin.Manifest.SupportsNetwork(a.Network())
}

// Plugins returns discovered plugin metadata for listing or detailed inspection.
func (a *App) PluginsInfo(_ context.Context, args []string) (*PluginsCommandResult, error) {
	var plugins []*discovery.Plugin
	var err error
	if a != nil && a.Plugins != nil {
		plugins, err = a.Plugins.DiscoverPluginsCached()
	} else {
		plugins, err = discovery.New().Discover()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to discover plugins: %w", err)
	}

	result := &PluginsCommandResult{
		Mode:    "list",
		Summary: Summary{Message: fmt.Sprintf("External Plugins (%d)", len(plugins))},
	}
	if len(plugins) == 0 {
		return result, nil
	}

	project := func(plugin *discovery.Plugin) PluginCommandSummary {
		summary := PluginCommandSummary{
			Name:        plugin.Manifest.Name,
			Version:     plugin.Manifest.Version,
			Description: plugin.Manifest.Description,
			Author:      plugin.Manifest.Author,
			Networks:    append([]string(nil), plugin.Manifest.Networks...),
			Commands:    make([]PluginExposedCommand, len(plugin.Manifest.Commands)),
		}
		for i, cmd := range plugin.Manifest.Commands {
			summary.Commands[i] = PluginExposedCommand{
				Name:        cmd.Name,
				Description: cmd.Description,
				Usage:       cmd.Usage,
			}
		}
		return summary
	}

	if len(args) == 1 {
		result.Mode = "show"
		for _, plugin := range plugins {
			if plugin.Manifest.Name == args[0] {
				summary := project(plugin)
				result.Plugin = &summary
				return result, nil
			}
		}
		return nil, fmt.Errorf("plugin not found: %s", args[0])
	}

	result.Plugins = make([]PluginCommandSummary, len(plugins))
	for i, plugin := range plugins {
		result.Plugins[i] = project(plugin)
	}
	return result, nil
}

// CompleterDeps returns the interactive completion dependencies backed by current engine state.
func (a *App) CompleterDeps() CompleterDeps {
	return CompleterDeps{
		AliasCache:        &a.eng.AliasCache,
		ASACache:          &a.eng.AsaCache,
		SetCache:          &a.eng.SetCache,
		SignerCache:       &a.eng.SignerCache,
		EnsureSignerCache: a.eng.EnsureSignerCache,
	}
}

// ConfigurePlugins updates plugin runtime configuration for the currently selected network.
func (a *App) ConfigurePlugins() error {
	if a == nil || a.Plugins == nil {
		return nil
	}

	algodURL := ""
	algodToken := ""
	if cfg, err := a.Config.GetAlgodConfig(a.Network()); err == nil && cfg != nil {
		algodURL = cfg.Server
		algodToken = cfg.Token
	}

	a.Plugins.SetConfig(a.Network(), algodURL, algodToken, "")
	return nil
}

// Balance returns balance information for one resolved address or alias.
func (a *App) BalanceForAddress(ctx context.Context, addressOrAlias string) (*BalanceDetails, error) {
	result, err := a.eng.GetBalanceWithContext(ctx, addressOrAlias)
	if err != nil {
		return nil, err
	}
	return balanceDetailsFromEngine(result), nil
}

// AllAddresses returns all known addresses from aliases and signer state.
func (a *App) AllAddresses(_ context.Context) ([]string, error) {
	return a.eng.ListAllAddresses()
}

// BindSignerClientContext attaches a request context to the current signer client when present.
// The returned cleanup function restores the prior client context state.
func (a *App) BindSignerClientContext(ctx context.Context) func() {
	if a == nil || a.eng == nil || a.eng.Connection == nil {
		return func() {}
	}
	return a.eng.Connection.BindSignerClientContext(ctx)
}
