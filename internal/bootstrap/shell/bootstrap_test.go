// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package shell

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/cache"
)

func TestLoadReturnsErrorWhenConfigMissing(t *testing.T) {
	tmpDir := t.TempDir()

	startup, err := Load(tmpDir, "")
	if err == nil {
		t.Fatal("expected missing config error")
	}
	if startup != nil {
		t.Fatal("expected nil startup on missing config")
	}
	if !strings.Contains(err.Error(), "config file not found") {
		t.Fatalf("expected missing config error, got %v", err)
	}
}

func TestLoadConfiguresStartupAndStorePaths(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	configYAML := []byte("network: testnet\nnetworks:\n  testnet:\n    algod:\n      server: http://localhost:4001\n")
	if err := os.WriteFile(configPath, configYAML, 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	startup, err := Load(tmpDir, "")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if startup.DataDir != tmpDir {
		t.Fatalf("DataDir = %q, want %q", startup.DataDir, tmpDir)
	}
	if startup.Network != "testnet" {
		t.Fatalf("Network = %q, want testnet", startup.Network)
	}

	gotCachePath := cache.GetASACacheFilenameForStore(cache.NewStore(startup.DataDir), "testnet")
	wantCachePath := filepath.Join(tmpDir, "cache", "testnet_asa_cache.json")
	if gotCachePath != wantCachePath {
		t.Fatalf("cache path = %q, want %q", gotCachePath, wantCachePath)
	}
}

func TestLoadRefusesLegacyClientEndpointConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	configYAML := []byte(`
network: testnet
ssh:
  host: signer.local
networks:
  testnet:
    algod:
      server: http://localhost:4001
`)
	if err := os.WriteFile(configPath, configYAML, 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	startup, err := Load(tmpDir, "")
	if err == nil {
		t.Fatal("Load() error = nil, want legacy endpoint config error")
	}
	if startup != nil {
		t.Fatalf("startup = %#v, want nil", startup)
	}
	if !strings.Contains(err.Error(), "legacy apclient endpoint config") {
		t.Fatalf("error = %v, want legacy endpoint config message", err)
	}
	if !strings.Contains(err.Error(), "endpoints.yaml") {
		t.Fatalf("error = %v, want endpoints.yaml instruction", err)
	}
	if _, statErr := os.Stat(filepath.Join(tmpDir, "endpoints.yaml")); !os.IsNotExist(statErr) {
		t.Fatalf("endpoints.yaml stat error = %v, want not exist", statErr)
	}
}

func TestLoadReturnsErrorWhenRequestedNetworkMissingFromAlgodConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	configYAML := []byte("network: testnet\nnetworks:\n  testnet:\n    algod:\n      server: http://localhost:4001\n")
	if err := os.WriteFile(configPath, configYAML, 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	startup, err := Load(tmpDir, "mainnet")
	if err == nil {
		t.Fatal("expected missing network config error")
	}
	if startup != nil {
		t.Fatal("expected nil startup on invalid network override")
	}
	if !strings.Contains(err.Error(), `network "mainnet" is not configured in config.yaml`) {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "configured networks: testnet") {
		t.Fatalf("expected configured networks in error, got %v", err)
	}
}
