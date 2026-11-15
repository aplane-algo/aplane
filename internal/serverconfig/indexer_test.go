// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package serverconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"
)

func loadServerConfigText(t *testing.T, text string) (ServerConfig, error) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(text), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return LoadServerConfig(dir)
}

func TestLoadServerConfigWithoutIndexerHasNone(t *testing.T) {
	cfg, err := loadServerConfigText(t, `
networks:
  testnet:
    algod:
      server: http://algod.example
`)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if got := cfg.GetIndexerConfig("testnet"); got != nil {
		t.Fatalf("GetIndexerConfig = %+v, want none", got)
	}
	if len(cfg.Indexer) != 0 {
		t.Fatalf("Indexer index = %+v, want empty", cfg.Indexer)
	}
}

func TestLoadServerConfigReadsTheIndexerBesideAlgod(t *testing.T) {
	cfg, err := loadServerConfigText(t, `
networks:
  mainnet:
    algod:
      server: https://configured-algod.example
    indexer:
      server: https://configured-indexer.example
      token: "secret-token"
  testnet:
    algod:
      server: https://algod.example
    indexer:
      server: ""
`)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	got := cfg.GetIndexerConfig("mainnet")
	if got == nil || got.Server != "https://configured-indexer.example" || got.Token != "secret-token" {
		t.Fatalf("mainnet Indexer = %+v", got)
	}
	// An empty server is no Indexer.
	if got := cfg.GetIndexerConfig("testnet"); got != nil {
		t.Fatalf("testnet Indexer = %+v, want none", got)
	}
	// The getter hands out a copy.
	got.Server = "changed"
	if cfg.GetIndexerConfig("mainnet").Server != "https://configured-indexer.example" {
		t.Fatal("GetIndexerConfig shared the configured entry")
	}
}

func TestLoadServerConfigRejectsAnIndexerURLNamingTheNetwork(t *testing.T) {
	for _, server := range []string{
		"configured-indexer.example:8980",
		"ftp://configured-indexer.example",
		"https://",
		"http://[::1",
		"https://user:secret-token@%zz",
	} {
		_, err := loadServerConfigText(t, `
networks:
  mainnet:
    indexer:
      server: "`+server+`"
`)
		if err == nil {
			t.Fatalf("server %q accepted", server)
		}
		if !strings.Contains(err.Error(), "networks.mainnet.indexer.server") {
			t.Fatalf("server %q: error %q does not name the network", server, err)
		}
		// The URL may hold a credential: the message does not repeat it.
		if strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), server) {
			t.Fatalf("server %q: error %q repeats the URL", server, err)
		}
	}
}

func TestServerConfigCloneCopiesTheIndexer(t *testing.T) {
	cfg := ServerConfig{
		Indexer: map[string]*apconfig.IndexerNetworkConfig{"mainnet": {Server: "https://idx", Token: "t"}},
		Networks: ServerNetworkConfigs{
			"mainnet": {Indexer: &apconfig.IndexerNetworkConfig{Server: "https://idx", Token: "t"}},
		},
	}
	clone := cfg.Clone()
	clone.Indexer["mainnet"].Server = "changed"
	clone.Networks["mainnet"].Indexer.Token = "changed"
	if cfg.Indexer["mainnet"].Server != "https://idx" {
		t.Fatal("Clone shared the Indexer index")
	}
	if cfg.Networks["mainnet"].Indexer.Token != "t" {
		t.Fatal("Clone shared the network's Indexer settings")
	}
}
