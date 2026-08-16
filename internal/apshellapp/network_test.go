// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
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

func (f *fakePluginRuntime) SignTransactions(string, jsonrpc.SignTransactionsParams) (*jsonrpc.SignTransactionsResult, error) {
	return nil, nil
}

func TestSwitchNetworkUpdatesEngineAndPlugins(t *testing.T) {
	cache.InitLogger()
	algod := newConsensusAlgodServer(t, string(protocol.ConsensusV42))
	defer algod.Close()

	cfg := config.DefaultConfig()
	cfg.NetworksAllowed = []string{"mainnet", "testnet"}
	cfg.Algod = config.AlgodConfig{
		"mainnet": &config.AlgodNetworkConfig{Server: algod.URL, Token: "main-token"},
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
	if plugins.algodURL != algod.URL || plugins.algodToken != "main-token" {
		t.Fatalf("plugin algod config = %q/%q", plugins.algodURL, plugins.algodToken)
	}
	if plugins.stopCalls != 1 {
		t.Fatalf("plugin stopCalls = %d, want 1", plugins.stopCalls)
	}
}

func TestSwitchNetworkRejectsUnsupportedConsensus(t *testing.T) {
	cache.InitLogger()
	algod := newConsensusAlgodServer(t, string(protocol.ConsensusV41))
	defer algod.Close()

	cfg := config.DefaultConfig()
	cfg.NetworksAllowed = []string{"mainnet", "testnet"}
	cfg.Algod = config.AlgodConfig{
		"mainnet": &config.AlgodNetworkConfig{Server: algod.URL},
	}
	eng, err := engine.NewInitializedEngine("testnet", &cfg, t.TempDir())
	if err != nil {
		t.Fatalf("NewInitializedEngine() error = %v", err)
	}
	app := New(eng, cfg, "/tmp/apclient")

	if _, err := app.SwitchNetwork(context.Background(), SwitchNetworkRequest{Network: "mainnet"}); err == nil {
		t.Fatal("SwitchNetwork() error = nil, want unsupported-consensus rejection")
	}
	if eng.GetNetwork() != "testnet" {
		t.Fatalf("engine network = %q, want unchanged testnet", eng.GetNetwork())
	}
}

func newConsensusAlgodServer(t *testing.T, consensus string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v2/transactions/params" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(models.TransactionParametersResponse{
			ConsensusVersion: consensus,
			Fee:              1_000,
			MinFee:           1_000,
			GenesisId:        "testnet-v1.0",
			GenesisHash:      make([]byte, 32),
			LastRound:        1,
		}); err != nil {
			t.Errorf("encode suggested params: %v", err)
		}
	}))
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
