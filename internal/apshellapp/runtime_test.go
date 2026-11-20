// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

func TestExecutionStateReflectsEngine(t *testing.T) {
	eng := engine.NewEngine("testnet")
	eng.SetWriteMode(true)
	eng.SetSimulate(true)

	app := New(eng, config.DefaultConfig(), t.TempDir())
	state := app.ExecutionState()

	if state.Network != "testnet" {
		t.Fatalf("state.Network = %q, want testnet", state.Network)
	}
	if !state.WriteMode {
		t.Fatal("state.WriteMode = false, want true")
	}
	if !state.Simulate {
		t.Fatal("state.Simulate = false, want true")
	}
	if state.IsConnected {
		t.Fatal("state.IsConnected = true, want false")
	}
}

func TestConfigurePluginsUsesCurrentNetworkConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Algod = config.AlgodConfig{
		"testnet": &config.AlgodNetworkConfig{Server: "https://testnet.example", Token: "test-token"},
	}

	eng := engine.NewEngine("testnet")

	plugins := &fakePluginRuntime{}
	app := New(eng, cfg, t.TempDir())
	app.Plugins = plugins

	app.ConfigurePlugins()
	if plugins.network != "testnet" {
		t.Fatalf("plugin network = %q, want testnet", plugins.network)
	}
	if plugins.algodURL != "https://testnet.example" || plugins.algodToken != "test-token" {
		t.Fatalf("plugin algod config = %q/%q", plugins.algodURL, plugins.algodToken)
	}
}

// A network with no algod settings gives plugins the network and empty algod
// settings.
func TestConfigurePluginsWithoutAlgodConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Algod = config.AlgodConfig{
		"mainnet": &config.AlgodNetworkConfig{Server: "https://mainnet.example", Token: "main-token"},
	}
	plugins := &fakePluginRuntime{algodURL: "stale", algodToken: "stale"}
	app := New(engine.NewEngine("testnet"), cfg, t.TempDir())
	app.Plugins = plugins

	app.ConfigurePlugins()
	if plugins.network != "testnet" || plugins.algodURL != "" || plugins.algodToken != "" {
		t.Fatalf("plugin config = %q %q/%q, want testnet with no algod", plugins.network, plugins.algodURL, plugins.algodToken)
	}
}
