// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package serverconfig

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"
)

func TestLoadServerConfigValidatesGenesisHashNetworks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(`
teal_compile_network: voi_mainnet
networks:
  voi_mainnet:
    algod:
      server: http://localhost:4001
    genesis_hash: "`+customGenesisHash(9)+`"
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	resolver, err := apconfig.NewGenesisHashNetworkResolver(cfg.GenesisHashNetworks)
	if err != nil {
		t.Fatalf("NewGenesisHashNetworkResolver: %v", err)
	}
	if network, ok := resolver.NetworkForGenesisHashBytes(testHashBytes(9)); !ok || network != "voi_mainnet" {
		t.Fatalf("NetworkForGenesisHashBytes = %q, %v; want voi_mainnet, true", network, ok)
	}
}

func TestLoadServerConfigAcceptsGroupedNetworkGenesisHash(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(`
teal_compile_network: localnet
networks:
  localnet:
    algod:
      server: http://localhost:4001
      token: token
    genesis_hash: "`+customGenesisHash(10)+`"
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if _, err := cfg.GetTEALCompileAlgod(); err != nil {
		t.Fatalf("GetTEALCompileAlgod: %v", err)
	}
	resolver, err := apconfig.NewGenesisHashNetworkResolver(cfg.GenesisHashNetworks)
	if err != nil {
		t.Fatalf("NewGenesisHashNetworkResolver: %v", err)
	}
	if network, ok := resolver.NetworkForGenesisHashBytes(testHashBytes(10)); !ok || network != "localnet" {
		t.Fatalf("NetworkForGenesisHashBytes = %q, %v; want localnet, true", network, ok)
	}
}

func TestLoadServerConfigRejectsGroupedGenesisHashConflict(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(`
networks:
  voi_mainnet:
    genesis_hash: "`+customGenesisHash(11)+`"
  localnet:
    genesis_hash: "`+customGenesisHash(11)+`"
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := LoadServerConfig(dir); err == nil {
		t.Fatal("LoadServerConfig conflict error = nil")
	}
}

func customGenesisHash(seed byte) string {
	canonical, err := apconfig.CanonicalGenesisHash(hex.EncodeToString(testHashBytes(seed)))
	if err != nil {
		panic(err)
	}
	return canonical
}

func testHashBytes(seed byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = seed
	}
	return out
}

// A bad network key is reported before any per-network setting, and a shared
// genesis hash names both networks.
func TestLoadServerConfigNetworkErrors(t *testing.T) {
	wantKeyErr := func() string {
		err := apconfig.ValidateNetworkID("bad net")
		if err == nil {
			t.Fatal("fixture: network key is valid")
		}
		return "invalid network in networks config: " + err.Error()
	}()
	for _, text := range []string{
		"networks:\n  \"bad net\":\n    algod:\n      server: http://localhost:4001\n",
		"networks:\n  \"bad net\":\n    indexer:\n      server: ftp://nope\n",
		"networks:\n  \"bad net\":\n    genesis_hash: \"" + customGenesisHash(12) + "\"\n  other:\n    genesis_hash: \"" + customGenesisHash(12) + "\"\n",
	} {
		_, err := loadServerConfigText(t, text)
		if err == nil || err.Error() != wantKeyErr {
			t.Fatalf("LoadServerConfig(%q) error = %v, want %q", text, err, wantKeyErr)
		}
	}
	_, err := loadServerConfigText(t, "networks:\n  voi_mainnet:\n    genesis_hash: \""+customGenesisHash(13)+"\"\n  localnet:\n    genesis_hash: \""+customGenesisHash(13)+"\"\n")
	hash := customGenesisHash(13)
	want1 := `invalid genesis_hash in networks config: genesis hash "` + hash + `" maps to both "voi_mainnet" and "localnet"`
	want2 := `invalid genesis_hash in networks config: genesis hash "` + hash + `" maps to both "localnet" and "voi_mainnet"`
	if err == nil || (err.Error() != want1 && err.Error() != want2) {
		t.Fatalf("conflict error = %v", err)
	}
	cfg, err := loadServerConfigText(t, "networks:\n  voi_mainnet:\n    genesis_hash: \""+hash+"\"\n  localnet:\n    algod:\n      server: http://localhost:4001\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Algod) != 1 || cfg.Algod["localnet"] == nil || len(cfg.GenesisHashNetworks) != 1 || cfg.GenesisHashNetworks[hash] != "voi_mainnet" {
		t.Fatalf("indexes = %+v, %+v", cfg.Algod, cfg.GenesisHashNetworks)
	}
}
