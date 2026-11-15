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

// The signer has no built-in Indexer: an install finds stages because the
// installer's config, like the example configs, names one for mainnet and
// testnet beside the algod endpoint of the same provider. An operator reads
// it there and can delete it.
func TestInstalledConfigsNameTheIndexerPreset(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	installer := mustReadTestFile(t, filepath.Join(repoRoot, "install.sh"))
	configs := map[string]string{
		"config.yaml.example":      string(mustReadTestFile(t, filepath.Join(repoRoot, "examples", "config", "apsigner", "config.yaml.example"))),
		"config.yaml.example.auto": string(mustReadTestFile(t, filepath.Join(repoRoot, "examples", "config", "apsigner", "config.yaml.example.auto"))),
		"install.sh": strings.NewReplacer(
			"$signer_port", "11270",
			"$ssh_port", "1127",
			"$require_memory_protection", "false",
			"$advertise_line", `  advertise_url: "ssh://cosigner.example:1127"`,
			"$listen_address", "0.0.0.0",
		).Replace(extractInstallHereDocAfter(t, string(installer), "write_signer_config() {", `cat > "$target" <<EOF`)),
	}
	for name, text := range configs {
		t.Run(name, func(t *testing.T) {
			cfg, err := loadServerConfigText(t, text)
			if err != nil {
				t.Fatalf("LoadServerConfig: %v", err)
			}
			for _, network := range []string{"mainnet", "testnet"} {
				got := cfg.GetIndexerConfig(network)
				want := "https://" + network + "-idx.4160.nodely.dev"
				if got == nil || got.Server != want || got.Token != "" {
					t.Errorf("%s Indexer = %+v, want %s with no token", network, got, want)
				}
				algod, err := cfg.GetAlgodConfig(network)
				if err != nil || algod.Server != "https://"+network+"-api.4160.nodely.dev" {
					t.Errorf("%s algod = %+v (%v): the Indexer preset sits beside the same provider's algod", network, algod, err)
				}
			}
			if got := cfg.GetIndexerConfig("localnet"); got != nil {
				t.Errorf("localnet Indexer = %+v, want none: aplocalnet writes it", got)
			}
		})
	}
}

// Deleting the entry is how the lookup is turned off: nothing stands in.
func TestNoIndexerEntryMeansNoIndexerOnPublicNetworks(t *testing.T) {
	cfg, err := loadServerConfigText(t, "networks:\n  mainnet:\n    algod:\n      server: https://mainnet-api.4160.nodely.dev\n  testnet: {}\n")
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	for _, network := range []string{"mainnet", "testnet", "betanet"} {
		if got := cfg.GetIndexerConfig(network); got != nil {
			t.Errorf("%s Indexer = %+v, want none without an entry", network, got)
		}
	}
	// A default would be put in Networks, which the index is built from.
	def := DefaultServerConfig()
	if len(def.Indexer) != 0 {
		t.Errorf("the default config names Indexers: %+v", def.Indexer)
	}
	for network, entry := range def.Networks {
		if entry != nil && entry.Indexer != nil {
			t.Errorf("the default config names an Indexer for %s: %+v", network, entry.Indexer)
		}
	}
	// And with no config file at all.
	none, err := LoadServerConfig(t.TempDir())
	if err != nil {
		t.Fatalf("LoadServerConfig with no file: %v", err)
	}
	for _, network := range []string{"mainnet", "testnet", "betanet"} {
		if got := none.GetIndexerConfig(network); got != nil {
			t.Errorf("%s Indexer with no config file = %+v, want none", network, got)
		}
	}
}
