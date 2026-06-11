// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateNetworkID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{name: "builtin", id: "testnet"},
		{name: "custom underscore", id: "voi_mainnet"},
		{name: "custom hyphen", id: "private-net1"},
		{name: "empty", id: "", wantErr: true},
		{name: "uppercase", id: "Testnet", wantErr: true},
		{name: "slash", id: "voi/mainnet", wantErr: true},
		{name: "leading underscore", id: "_voi", wantErr: true},
		{name: "leading hyphen", id: "-voi", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNetworkID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateNetworkID(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
			}
		})
	}
}

func TestCanonicalGenesisHashAcceptsBase64AndHex(t *testing.T) {
	raw := testHashBytes(1)
	want := AlgorandMainnetGenesisHash
	got, err := CanonicalGenesisHash(AlgorandMainnetGenesisHash)
	if err != nil {
		t.Fatalf("CanonicalGenesisHash(base64): %v", err)
	}
	if got != want {
		t.Fatalf("base64 canonical = %q, want %q", got, want)
	}

	hexHash := hex.EncodeToString(raw)
	got, err = CanonicalGenesisHash(hexHash)
	if err != nil {
		t.Fatalf("CanonicalGenesisHash(hex): %v", err)
	}
	want = base64.StdEncoding.EncodeToString(raw)
	if got != want {
		t.Fatalf("hex canonical = %q, want %q", got, want)
	}
}

func TestGenesisHashNetworkResolverRejectsReservedOverrides(t *testing.T) {
	if _, err := NewGenesisHashNetworkResolver(map[string]string{customGenesisHash(4): NetworkMainnet}); err == nil {
		t.Fatal("custom hash mapped to reserved token error = nil")
	}
	if _, err := NewGenesisHashNetworkResolver(map[string]string{AlgorandMainnetGenesisHash: "voi_mainnet"}); err == nil {
		t.Fatal("built-in hash remap error = nil")
	}
}

func TestGenesisHashNetworkResolverRejectsDuplicateToken(t *testing.T) {
	_, err := NewGenesisHashNetworkResolver(map[string]string{
		customGenesisHash(7): "voi_mainnet",
		customGenesisHash(8): "voi_mainnet",
	})
	if err == nil {
		t.Fatal("duplicate token error = nil")
	}
}

func TestLoadConfigAcceptsCustomNetworkTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(`
network: voi_mainnet
networks_allowed: [voi_mainnet]
networks:
  voi_mainnet:
    algod:
      server: http://localhost:4001
      token: token
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadConfigFromPath(path)
	if err != nil {
		t.Fatalf("LoadConfigFromPath: %v", err)
	}
	if cfg.Network != "voi_mainnet" {
		t.Fatalf("Network = %q, want voi_mainnet", cfg.Network)
	}
	if _, err := cfg.GetAlgodConfig("voi_mainnet"); err != nil {
		t.Fatalf("GetAlgodConfig(custom): %v", err)
	}
}

func TestLoadConfigAcceptsGroupedNetworkAlgod(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(`
network: voi_mainnet
networks_allowed: [voi_mainnet]
networks:
  voi_mainnet:
    algod:
      server: http://localhost:4001
      token: token
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadConfigFromPath(path)
	if err != nil {
		t.Fatalf("LoadConfigFromPath: %v", err)
	}
	algodCfg, err := cfg.GetAlgodConfig("voi_mainnet")
	if err != nil {
		t.Fatalf("GetAlgodConfig(grouped): %v", err)
	}
	if algodCfg.Server != "http://localhost:4001" {
		t.Fatalf("Algod server = %q, want http://localhost:4001", algodCfg.Server)
	}
}

func customGenesisHash(seed byte) string {
	canonical, err := CanonicalGenesisHash(hex.EncodeToString(testHashBytes(seed)))
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
