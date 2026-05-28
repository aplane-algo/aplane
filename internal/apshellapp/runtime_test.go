// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

func TestExecutionStateReflectsEngine(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
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
	if state.IsTunnelBound {
		t.Fatal("state.IsTunnelBound = true, want false")
	}
}

func TestConfigurePluginsUsesCurrentNetworkConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Algod = config.AlgodConfig{
		"testnet": &config.AlgodNetworkConfig{Server: "https://testnet.example", Token: "test-token"},
	}

	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	plugins := &fakePluginRuntime{}
	app := New(eng, cfg, t.TempDir())
	app.Plugins = plugins

	if err := app.ConfigurePlugins(); err != nil {
		t.Fatalf("ConfigurePlugins() error = %v", err)
	}
	if plugins.network != "testnet" {
		t.Fatalf("plugin network = %q, want testnet", plugins.network)
	}
	if plugins.algodURL != "https://testnet.example" || plugins.algodToken != "test-token" {
		t.Fatalf("plugin algod config = %q/%q", plugins.algodURL, plugins.algodToken)
	}
}
