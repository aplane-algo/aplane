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
