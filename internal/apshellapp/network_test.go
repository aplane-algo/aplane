// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

type fakePluginRuntime struct {
	network         string
	algodURL        string
	algodToken      string
	stopCalls       int
	plugins         []*discovery.Plugin
	cachedDiscCalls int
}

func (f *fakePluginRuntime) SetConfig(network, algodURL, algodToken string) {
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

func (f *fakePluginRuntime) ExecuteCommand(context.Context, string, string, []string, jsonrpc.Context) (*jsonrpc.ExecuteResult, error) {
	return nil, nil
}

func (f *fakePluginRuntime) SignTransactions(context.Context, string, jsonrpc.SignTransactionsParams) (*jsonrpc.SignTransactionsResult, error) {
	return nil, nil
}

func TestSwitchNetworkUpdatesEngineAndPlugins(t *testing.T) {
	algod := newConsensusAlgodServer(t, string(protocol.ConsensusV42), genesisHashBytes(t, config.AlgorandMainnetGenesisHash))
	defer algod.Close()

	cfg := config.DefaultConfig()
	cfg.NetworksAllowed = []string{"mainnet", "testnet"}
	cfg.Algod = config.AlgodConfig{
		"mainnet": &config.AlgodNetworkConfig{Server: algod.URL, Token: "main-token"},
	}
	eng := engine.NewInitializedEngine("testnet", &cfg, t.TempDir())

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

// A reserved name whose algod serves another chain is refused before the
// switch touches anything: the engine keeps its network and algod, plugins keep
// running, and no account is read into the reserved network's auth cache.
func TestSwitchNetworkRefusesAReservedNameForAnotherChain(t *testing.T) {
	algod := newConsensusAlgodServer(t, string(protocol.ConsensusV42), genesisHashBytes(t, config.AlgorandTestnetGenesisHash))
	defer algod.Close()

	cfg := config.DefaultConfig()
	cfg.Algod = config.AlgodConfig{
		"mainnet": &config.AlgodNetworkConfig{Server: algod.URL},
	}
	dataDir := t.TempDir()
	eng := engine.NewInitializedEngine("testnet", &cfg, dataDir)
	if err := eng.PopulateSignerCache([]signerapi.KeyInfo{
		{Address: crypto.GenerateAccount().Address.String(), KeyType: "ed25519", AuthorizationKind: "ed25519"},
	}); err != nil {
		t.Fatalf("PopulateSignerCache() error = %v", err)
	}
	oldClient := eng.AlgodClient
	plugins := &fakePluginRuntime{}
	app := New(eng, cfg, dataDir)
	app.Plugins = plugins

	res, err := app.SwitchNetwork(context.Background(), SwitchNetworkRequest{Network: "mainnet"})
	want := `cannot switch to mainnet: network name "mainnet" is reserved for Algorand's mainnet, but its algod's genesis hash is ` +
		config.AlgorandTestnetGenesisHash + " (testnet)"
	if err == nil || err.Error() != want {
		t.Fatalf("SwitchNetwork() = (%+v, %v), want %q", res, err, want)
	}
	if eng.GetNetwork() != "testnet" || eng.AlgodClient != oldClient {
		t.Fatalf("engine network = %q, client replaced = %v, want testnet and its own client", eng.GetNetwork(), eng.AlgodClient != oldClient)
	}
	if plugins.network != "" || plugins.stopCalls != 0 {
		t.Fatalf("plugins = %+v, want them left alone", plugins)
	}
	if got := algod.otherCalls.Load(); got != 0 {
		t.Fatalf("algod calls other than suggested parameters = %d, want 0", got)
	}
	if path := filepath.Join(dataDir, "cache", "mainnet_auth_cache.json"); fileExists(path) {
		t.Fatalf("%s was written by a refused switch", path)
	}
}

// A custom name may stand for any chain, a reserved network's included.
func TestSwitchNetworkAllowsACustomNameForAnyChain(t *testing.T) {
	for name, genesisHash := range map[string][]byte{
		"private chain": make([]byte, 32),
		"mainnet":       genesisHashBytes(t, config.AlgorandMainnetGenesisHash),
	} {
		t.Run(name, func(t *testing.T) {
			algod := newConsensusAlgodServer(t, string(protocol.ConsensusV42), genesisHash)
			defer algod.Close()
			cfg := config.DefaultConfig()
			cfg.Algod = config.AlgodConfig{"my-network": &config.AlgodNetworkConfig{Server: algod.URL}}
			eng := engine.NewInitializedEngine("testnet", &cfg, t.TempDir())
			if _, err := New(eng, cfg, "/tmp/apclient").SwitchNetwork(context.Background(), SwitchNetworkRequest{Network: "my-network"}); err != nil {
				t.Fatalf("SwitchNetwork() error = %v", err)
			}
			if eng.GetNetwork() != "my-network" {
				t.Fatalf("engine network = %q, want my-network", eng.GetNetwork())
			}
		})
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestSwitchNetworkRejectsUnsupportedConsensus(t *testing.T) {
	algod := newConsensusAlgodServer(t, string(protocol.ConsensusV41), genesisHashBytes(t, config.AlgorandMainnetGenesisHash))
	defer algod.Close()

	cfg := config.DefaultConfig()
	cfg.NetworksAllowed = []string{"mainnet", "testnet"}
	cfg.Algod = config.AlgodConfig{
		"mainnet": &config.AlgodNetworkConfig{Server: algod.URL},
	}
	eng := engine.NewInitializedEngine("testnet", &cfg, t.TempDir())
	app := New(eng, cfg, "/tmp/apclient")

	if _, err := app.SwitchNetwork(context.Background(), SwitchNetworkRequest{Network: "mainnet"}); err == nil || !strings.Contains(err.Error(), "is unsupported by this APlane release") {
		t.Fatalf("SwitchNetwork() error = %v, want unsupported-consensus rejection", err)
	}
	if eng.GetNetwork() != "testnet" {
		t.Fatalf("engine network = %q, want unchanged testnet", eng.GetNetwork())
	}
}

func genesisHashBytes(t *testing.T, encoded string) []byte {
	t.Helper()
	hash, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode genesis hash: %v", err)
	}
	return hash
}

// consensusAlgodServer answers suggested parameters and counts any other call.
type consensusAlgodServer struct {
	*httptest.Server
	otherCalls atomic.Int32
}

func newConsensusAlgodServer(t *testing.T, consensus string, genesisHash []byte) *consensusAlgodServer {
	t.Helper()
	server := &consensusAlgodServer{}
	server.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v2/transactions/params" {
			server.otherCalls.Add(1)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(models.TransactionParametersResponse{
			ConsensusVersion: consensus,
			Fee:              1_000,
			MinFee:           1_000,
			GenesisHash:      genesisHash,
			LastRound:        1,
		}); err != nil {
			t.Errorf("encode suggested params: %v", err)
		}
	}))
	return server
}

func TestSwitchNetworkRejectsDisallowedNetwork(t *testing.T) {

	cfg := config.DefaultConfig()
	cfg.NetworksAllowed = []string{"testnet"}
	eng := engine.NewInitializedEngine("testnet", &cfg, t.TempDir())
	app := New(eng, cfg, "/tmp/apclient")

	if _, err := app.SwitchNetwork(context.Background(), SwitchNetworkRequest{Network: "mainnet"}); err == nil {
		t.Fatal("SwitchNetwork() error = nil, want disallowed network error")
	}
}
