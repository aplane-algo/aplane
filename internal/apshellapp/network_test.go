// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"testing"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
)

type fakePluginRuntime struct {
	network         string
	algodURL        string
	algodToken      string
	stopCalls       int
	plugins         []*discovery.Plugin
	cachedDiscCalls int
}

func (f *fakePluginRuntime) SetConfig(network, algodURL, algodToken, _ string) {
	f.network = network
	f.algodURL = algodURL
	f.algodToken = algodToken
}

func (f *fakePluginRuntime) StopAll() {
	f.stopCalls++
}

func (f *fakePluginRuntime) DiscoverPluginsCached() ([]*discovery.Plugin, error) {
	f.cachedDiscCalls++
	return f.plugins, nil
}

func (f *fakePluginRuntime) FindByCommand(string) (*discovery.Plugin, error) {
	return nil, nil
}

func (f *fakePluginRuntime) FindByName(string) (*discovery.Plugin, error) {
	return nil, nil
}

func (f *fakePluginRuntime) ListCommands() ([]string, error) {
	return nil, nil
}

func (f *fakePluginRuntime) ExecuteCommand(string, string, []string, jsonrpc.Context) (*jsonrpc.ExecuteResult, error) {
	return nil, nil
}

func TestSwitchNetworkUpdatesEngineAndPlugins(t *testing.T) {
	cache.InitLogger()

	cfg := config.DefaultConfig()
	cfg.NetworksAllowed = []string{"mainnet", "testnet"}
	cfg.Algod = config.AlgodConfig{
		"mainnet": &config.AlgodNetworkConfig{Server: "https://mainnet.example", Token: "main-token"},
	}
	eng, err := engine.NewInitializedEngine("testnet", &cfg, t.TempDir())
	if err != nil {
		t.Fatalf("NewInitializedEngine() error = %v", err)
	}

	plugins := &fakePluginRuntime{}
	app := New(eng, cfg, "/tmp/apclient")
	app.Plugins = plugins

	res, err := app.SwitchNetwork(context.Background(), SwitchNetworkRequest{Network: "mainnet"})
	if err != nil {
		t.Fatalf("SwitchNetwork() error = %v", err)
	}

	if eng.GetNetwork() != "mainnet" {
		t.Fatalf("engine network = %q, want mainnet", eng.GetNetwork())
	}
	if res.OldNetwork != "testnet" || res.NewNetwork != "mainnet" {
		t.Fatalf("result = %#v", res)
	}
	if plugins.network != "mainnet" {
		t.Fatalf("plugin network = %q, want mainnet", plugins.network)
	}
	if plugins.algodURL != "https://mainnet.example" || plugins.algodToken != "main-token" {
		t.Fatalf("plugin algod config = %q/%q", plugins.algodURL, plugins.algodToken)
	}
	if plugins.stopCalls != 1 {
		t.Fatalf("plugin stopCalls = %d, want 1", plugins.stopCalls)
	}
}

func TestSwitchNetworkRejectsDisallowedNetwork(t *testing.T) {
	cache.InitLogger()

	cfg := config.DefaultConfig()
	cfg.NetworksAllowed = []string{"testnet"}
	eng, err := engine.NewInitializedEngine("testnet", &cfg, t.TempDir())
	if err != nil {
		t.Fatalf("NewInitializedEngine() error = %v", err)
	}
	app := New(eng, cfg, "/tmp/apclient")

	if _, err := app.SwitchNetwork(context.Background(), SwitchNetworkRequest{Network: "mainnet"}); err == nil {
		t.Fatal("SwitchNetwork() error = nil, want disallowed network error")
	}
}
