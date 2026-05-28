// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"testing"

	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/manifest"
)

func TestPluginsInfoListsDiscoveredPlugins(t *testing.T) {
	plugins := &fakePluginRuntime{
		plugins: []*discovery.Plugin{
			{
				Manifest: &manifest.Manifest{
					Name:        "swap-tools",
					Version:     "1.2.3",
					Description: "swap helpers",
					Author:      "ops",
					Networks:    []string{"testnet"},
					Commands: []manifest.Command{
						{Name: "swap", Description: "swap command", Usage: "swap <pair>"},
					},
				},
			},
		},
	}
	app := &App{
		Plugins: plugins,
	}

	result, err := app.PluginsInfo(context.Background(), nil)
	if err != nil {
		t.Fatalf("PluginsInfo() error = %v", err)
	}
	if result.Mode != "list" {
		t.Fatalf("mode = %q, want list", result.Mode)
	}
	if len(result.Plugins) != 1 {
		t.Fatalf("len(Plugins) = %d, want 1", len(result.Plugins))
	}
	if result.Plugins[0].Name != "swap-tools" {
		t.Fatalf("plugin name = %q, want swap-tools", result.Plugins[0].Name)
	}
	if len(result.Plugins[0].Commands) != 1 || result.Plugins[0].Commands[0].Name != "swap" {
		t.Fatalf("commands = %#v", result.Plugins[0].Commands)
	}
	if plugins.cachedDiscCalls != 1 {
		t.Fatalf("cached discovery calls = %d, want 1", plugins.cachedDiscCalls)
	}
}

func TestPluginsInfoShowsSinglePlugin(t *testing.T) {
	app := &App{
		Plugins: &fakePluginRuntime{
			plugins: []*discovery.Plugin{
				{Manifest: &manifest.Manifest{
					Name:        "swap-tools",
					Version:     "1.2.3",
					Description: "swap helpers",
					Commands:    []manifest.Command{{Name: "swap", Description: "swap command"}},
				}},
			},
		},
	}

	result, err := app.PluginsInfo(context.Background(), []string{"swap-tools"})
	if err != nil {
		t.Fatalf("PluginsInfo(show) error = %v", err)
	}
	if result.Mode != "show" {
		t.Fatalf("mode = %q, want show", result.Mode)
	}
	if result.Plugin == nil || result.Plugin.Name != "swap-tools" {
		t.Fatalf("plugin = %#v, want swap-tools", result.Plugin)
	}
}
