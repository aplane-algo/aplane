// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package aplocalnet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"gopkg.in/yaml.v3"
)

func TestApplyRequiresAtLeastOneTarget(t *testing.T) {
	_, err := Apply(context.Background(), Options{})
	if err == nil || !strings.Contains(err.Error(), "at least one") {
		t.Fatalf("Apply() error = %v, want target requirement", err)
	}
}

func TestNormalizeOptionsUsesAlgodOverrides(t *testing.T) {
	t.Setenv("APLANE_LOCALNET_ALGOD_URL", " http://localhost:4011/ ")
	t.Setenv("APLANE_LOCALNET_KMD_URL", " http://localhost:4012/ ")
	t.Setenv("APLANE_LOCALNET_TOKEN", "env-token")
	t.Setenv("APLANE_LOCALNET_INDEXER_URL", " http://localhost:8990/ ")

	opts := NormalizeOptions(Options{})
	if opts.IndexerURL != "http://localhost:8990" {
		t.Fatalf("IndexerURL = %q, want %q", opts.IndexerURL, "http://localhost:8990")
	}
	if opts.AlgodURL != "http://localhost:4011" {
		t.Fatalf("AlgodURL = %q, want %q", opts.AlgodURL, "http://localhost:4011")
	}
	if opts.AlgodToken != "env-token" {
		t.Fatalf("AlgodToken = %q, want env-token", opts.AlgodToken)
	}
	if opts.KMDURL != "http://localhost:4012" {
		t.Fatalf("KMDURL = %q, want %q", opts.KMDURL, "http://localhost:4012")
	}

	opts = NormalizeOptions(Options{
		AlgodURL:   " http://localhost:4012/ ",
		AlgodToken: "flag-token",
		KMDURL:     " http://localhost:4013/ ",
		IndexerURL: " http://localhost:8991/ ",
	})
	if opts.IndexerURL != "http://localhost:8991" {
		t.Fatalf("flag IndexerURL = %q, want %q", opts.IndexerURL, "http://localhost:8991")
	}
	if opts.AlgodURL != "http://localhost:4012" {
		t.Fatalf("flag AlgodURL = %q, want %q", opts.AlgodURL, "http://localhost:4012")
	}
	if opts.AlgodToken != "flag-token" {
		t.Fatalf("flag AlgodToken = %q, want flag-token", opts.AlgodToken)
	}
	if opts.KMDURL != "http://localhost:4013" {
		t.Fatalf("flag KMDURL = %q, want %q", opts.KMDURL, "http://localhost:4013")
	}
}

func TestEnsureSignerLocalnetConfigWritesNetwork(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	newHash := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	initial := `user_auto_approve: false
networks:
  testnet:
    algod:
      server: https://testnet.example
      token: ""
`
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(initial), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	info := LocalNetInfo{
		AlgodURL:    "http://localhost:4001",
		GenesisID:   "devnet-v1",
		GenesisHash: newHash,
		LastRound:   123,
	}
	changed, path, err := EnsureSignerLocalnetConfig(dir, info, DefaultAlgodToken, DefaultIndexerURL)
	if err != nil {
		t.Fatalf("EnsureSignerLocalnetConfig: %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}
	if path != filepath.Join(dir, "config.yaml") {
		t.Fatalf("path = %q", path)
	}

	cfg, err := serverconfig.LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	localnet := cfg.Networks[NetworkID]
	if localnet == nil || localnet.Algod == nil {
		t.Fatalf("localnet config missing: %#v", cfg.Networks)
	}
	if localnet.Algod.Server != info.AlgodURL {
		t.Fatalf("localnet algod server = %q, want %q", localnet.Algod.Server, info.AlgodURL)
	}
	if localnet.Algod.Token != DefaultAlgodToken {
		t.Fatalf("localnet token = %q", localnet.Algod.Token)
	}
	if localnet.GenesisHash != newHash {
		t.Fatalf("localnet genesis_hash = %q, want %q", localnet.GenesisHash, newHash)
	}
	if idx := cfg.GetIndexerConfig(NetworkID); idx == nil || idx.Server != DefaultIndexerURL || idx.Token != DefaultAlgodToken {
		t.Fatalf("localnet indexer = %#v, want %s with the LocalNet token", idx, DefaultIndexerURL)
	}
	configInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(config): %v", err)
	}
	if got := configInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("signer config mode = %04o, want 0600", got)
	}

	changed, _, err = EnsureSignerLocalnetConfig(dir, info, DefaultAlgodToken, DefaultIndexerURL)
	if err != nil {
		t.Fatalf("EnsureSignerLocalnetConfig second call: %v", err)
	}
	if changed {
		t.Fatal("second call changed config, want idempotent no-op")
	}
}

func TestEnsurePluginActivatedAddsLocalnetPlugin(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	initial := "enabled_plugins:\n  - reti\n"
	if err := os.WriteFile(filepath.Join(dir, discovery.ActivationConfigName), []byte(initial), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	changed, path, err := EnsurePluginActivated(dir)
	if err != nil {
		t.Fatalf("EnsurePluginActivated: %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}
	if path != filepath.Join(dir, discovery.ActivationConfigName) {
		t.Fatalf("path = %q", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var cfg struct {
		EnabledPlugins []string `yaml:"enabled_plugins"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	got := strings.Join(cfg.EnabledPlugins, ",")
	if got != "reti,algokit-localnet" {
		t.Fatalf("enabled_plugins = %q, want reti,algokit-localnet", got)
	}

	changed, _, err = EnsurePluginActivated(dir)
	if err != nil {
		t.Fatalf("EnsurePluginActivated second call: %v", err)
	}
	if changed {
		t.Fatal("second call changed plugins.yaml, want idempotent no-op")
	}
}

func TestEnsureClientLocalnetConfigSetsDefaultAndAllowsLocalnet(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	initial := `network: testnet
networks_allowed:
  - mainnet
  - testnet
networks:
  testnet:
    algod:
      server: https://testnet.example
      token: ""
`
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(initial), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	info := LocalNetInfo{
		AlgodURL:    "http://localhost:4001",
		GenesisID:   "devnet-v1",
		GenesisHash: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
		LastRound:   123,
	}
	changed, path, err := EnsureClientLocalnetConfig(dir, info, DefaultAlgodToken)
	if err != nil {
		t.Fatalf("EnsureClientLocalnetConfig: %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}
	if path != filepath.Join(dir, "config.yaml") {
		t.Fatalf("path = %q", path)
	}

	cfg, err := apconfig.LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Network != NetworkID {
		t.Fatalf("network = %q, want %q", cfg.Network, NetworkID)
	}
	if !cfg.IsNetworkAllowed(NetworkID) {
		t.Fatalf("%q was not added to networks_allowed: %#v", NetworkID, cfg.NetworksAllowed)
	}
	algodCfg, err := cfg.GetAlgodConfig(NetworkID)
	if err != nil {
		t.Fatalf("GetAlgodConfig(%s): %v", NetworkID, err)
	}
	if algodCfg.Server != info.AlgodURL || algodCfg.Token != DefaultAlgodToken {
		t.Fatalf("localnet algod = %#v, want %q/%q", algodCfg, info.AlgodURL, DefaultAlgodToken)
	}

	changed, _, err = EnsureClientLocalnetConfig(dir, info, DefaultAlgodToken)
	if err != nil {
		t.Fatalf("EnsureClientLocalnetConfig second call: %v", err)
	}
	if changed {
		t.Fatal("second call changed config, want idempotent no-op")
	}
}

func TestEnsureClientLocalnetConfigCreatesConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	info := LocalNetInfo{AlgodURL: "http://localhost:4001"}
	changed, path, err := EnsureClientLocalnetConfig(dir, info, DefaultAlgodToken)
	if err != nil {
		t.Fatalf("EnsureClientLocalnetConfig: %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	text := string(data)
	for _, want := range []string{"network: localnet", "localnet:", "server: http://localhost:4001"} {
		if !strings.Contains(text, want) {
			t.Fatalf("config missing %q:\n%s", want, text)
		}
	}
}

func TestEnsurePluginActivatedCreatesConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	changed, path, err := EnsurePluginActivated(dir)
	if err != nil {
		t.Fatalf("EnsurePluginActivated: %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "- algokit-localnet") {
		t.Fatalf("plugins.yaml does not enable localnet plugin:\n%s", data)
	}
}

func TestEnsureLocalnetEnvConfigWritesKMDURL(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	clientDir := filepath.Join(root, "apclient")
	if err := os.MkdirAll(clientDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	envPath := filepath.Join(root, "apenv.sh")
	initial := `export APSIGNER_DATA='/tmp/signer'
export APCLIENT_DATA='/tmp/client'
`
	if err := os.WriteFile(envPath, []byte(initial), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	changed, path, warnings, err := EnsureLocalnetEnvConfig(clientDir, " http://localhost:4012/ ")
	if err != nil {
		t.Fatalf("EnsureLocalnetEnvConfig: %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}
	if path != envPath {
		t.Fatalf("path = %q, want %q", path, envPath)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", warnings)
	}
	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "export APLANE_LOCALNET_KMD_URL='http://localhost:4012'\n") {
		t.Fatalf("apenv.sh missing KMD export:\n%s", data)
	}

	changed, _, warnings, err = EnsureLocalnetEnvConfig(clientDir, "http://localhost:4012")
	if err != nil {
		t.Fatalf("EnsureLocalnetEnvConfig second call: %v", err)
	}
	if changed {
		t.Fatal("second call changed env config, want idempotent no-op")
	}
	if len(warnings) != 0 {
		t.Fatalf("second warnings = %#v, want none", warnings)
	}

	changed, _, warnings, err = EnsureLocalnetEnvConfig(clientDir, "http://localhost:4013")
	if err != nil {
		t.Fatalf("EnsureLocalnetEnvConfig replace call: %v", err)
	}
	if !changed {
		t.Fatal("replace call changed = false, want true")
	}
	if len(warnings) != 0 {
		t.Fatalf("replace warnings = %#v, want none", warnings)
	}
	data, err = os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("ReadFile after replace: %v", err)
	}
	text := string(data)
	if strings.Contains(text, "http://localhost:4012") ||
		!strings.Contains(text, "export APLANE_LOCALNET_KMD_URL='http://localhost:4013'\n") {
		t.Fatalf("apenv.sh did not replace KMD export:\n%s", text)
	}
}

func TestEnsureLocalnetEnvConfigWarnsWhenEnvScriptMissing(t *testing.T) {
	t.Parallel()

	clientDir := filepath.Join(t.TempDir(), "apclient")
	if err := os.MkdirAll(clientDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	changed, path, warnings, err := EnsureLocalnetEnvConfig(clientDir, "http://localhost:4012")
	if err != nil {
		t.Fatalf("EnsureLocalnetEnvConfig: %v", err)
	}
	if changed {
		t.Fatal("changed = true, want false")
	}
	if path != "" {
		t.Fatalf("path = %q, want empty", path)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "APLANE_LOCALNET_KMD_URL") {
		t.Fatalf("warnings = %#v, want KMD env warning", warnings)
	}
}

func TestClientConfigWarningsReportsLocalnetDisallowed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configData := `network: testnet
networks_allowed:
  - mainnet
  - testnet
`
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(configData), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	warnings := clientConfigWarnings(dir)
	if len(warnings) != 1 {
		t.Fatalf("warnings = %#v, want one warning", warnings)
	}
	if !strings.Contains(warnings[0], "networks_allowed") || !strings.Contains(warnings[0], NetworkID) {
		t.Fatalf("warning = %q, want networks_allowed/localnet", warnings[0])
	}
}

func TestNormalizeOptionsLeavesTheIndexerUnsetWithoutFlagOrEnv(t *testing.T) {
	t.Setenv("APLANE_LOCALNET_INDEXER_URL", "")
	if opts := NormalizeOptions(Options{}); opts.IndexerURL != "" {
		t.Fatalf("IndexerURL = %q, want none given", opts.IndexerURL)
	}
}

const testLocalnetGenesis = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="

// writeSignerConfig writes text as the signer's config.yaml and returns the
// directory.
func writeSignerConfig(t *testing.T, text string) string {
	t.Helper()
	dir := t.TempDir()
	if text != "" {
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func localnetIndexer(t *testing.T, dir string) *serverconfig.ServerNetworkConfig {
	t.Helper()
	cfg, err := serverconfig.LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	return cfg.Networks[NetworkID]
}

func TestEnsureSignerLocalnetConfigIndexerRules(t *testing.T) {
	info := LocalNetInfo{AlgodURL: "http://localhost:4001", GenesisHash: testLocalnetGenesis}
	operators := `networks:
  localnet:
    indexer:
      server: http://indexer.example:8980
      token: "kept"
`
	emptied := `networks:
  localnet:
    indexer:
      server: ""
`
	for _, tc := range []struct {
		name, config, given string
		wantServer          string
		wantToken           string
	}{
		{"none given, no entry: the default", "", "", DefaultIndexerURL, DefaultAlgodToken},
		{"none given, the operator's entry: left alone", operators, "", "http://indexer.example:8980", "kept"},
		{"none given, an emptied entry: left off", emptied, "", "", ""},
		{"given: written over the operator's entry", operators, "http://localhost:8990", "http://localhost:8990", DefaultAlgodToken},
		{"given, no entry: written", "", "http://localhost:8990", "http://localhost:8990", DefaultAlgodToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeSignerConfig(t, tc.config)
			if _, _, err := EnsureSignerLocalnetConfig(dir, info, DefaultAlgodToken, tc.given); err != nil {
				t.Fatal(err)
			}
			localnet := localnetIndexer(t, dir)
			if localnet == nil || localnet.Indexer == nil {
				if tc.wantServer == "" && tc.config == "" {
					return
				}
				t.Fatalf("localnet = %#v, want an indexer entry", localnet)
			}
			if localnet.Indexer.Server != tc.wantServer || localnet.Indexer.Token != tc.wantToken {
				t.Fatalf("indexer = %#v, want server %q token %q", localnet.Indexer, tc.wantServer, tc.wantToken)
			}
			// A second apply with the same input changes nothing.
			changed, _, err := EnsureSignerLocalnetConfig(dir, info, DefaultAlgodToken, tc.given)
			if err != nil || changed {
				t.Fatalf("second apply changed %v, err %v", changed, err)
			}
		})
	}
}

// An Indexer URL the signer would refuse is refused before anything is
// written, without repeating it.
func TestIndexerURLTheSignerWouldRefuseIsRefused(t *testing.T) {
	info := LocalNetInfo{AlgodURL: "http://localhost:4001", GenesisHash: testLocalnetGenesis}
	for _, bad := range []string{"localhost:8980", "ftp://indexer.example", "http://", "indexer.example"} {
		err := ValidateOptions(Options{IndexerURL: bad})
		if err == nil || !strings.Contains(err.Error(), "--indexer-url") || !strings.Contains(err.Error(), "http or https URL with a host") {
			t.Fatalf("%q: ValidateOptions = %v", bad, err)
		}
		dir := writeSignerConfig(t, "")
		if _, _, err := EnsureSignerLocalnetConfig(dir, info, DefaultAlgodToken, bad); err == nil {
			t.Fatalf("%q: written", bad)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "config.yaml")); !os.IsNotExist(statErr) {
			t.Fatalf("%q: config written despite the refusal", bad)
		}
		// Apply refuses it before it reaches for algod.
		if _, err := Apply(context.Background(), Options{SignerDataDir: dir, IndexerURL: bad, AlgodURL: "http://127.0.0.1:1"}); err == nil || !strings.Contains(err.Error(), "--indexer-url") {
			t.Fatalf("%q: Apply = %v", bad, err)
		}
	}
	// The signer's own loader refuses the same values.
	dir := writeSignerConfig(t, "networks:\n  localnet:\n    indexer:\n      server: localhost:8980\n")
	if _, err := serverconfig.LoadServerConfig(dir); err == nil {
		t.Fatal("the signer's loader accepted localhost:8980")
	}
}
