// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"os"
	"testing"

	"github.com/aplane-algo/aplane/internal/cache"
)

var testCacheStore *cache.Store

func TestMain(m *testing.M) {
	cache.InitLogger()

	// Use a temp directory for cache files so tests don't create
	// a "cache/" directory inside the source tree.
	tmpDir, err := os.MkdirTemp("", "engine-test-cache-*")
	if err != nil {
		panic("failed to create temp cache dir: " + err.Error())
	}
	testCacheStore = cache.NewStore(tmpDir)
	// Some engine tests still exercise cwd-relative cache paths. Keep those
	// writes in the same temp cache root used by store-backed helpers.
	if err := os.Chdir(tmpDir); err != nil {
		panic("failed to chdir to temp engine test dir: " + err.Error())
	}
	code := m.Run()
	_ = os.RemoveAll(tmpDir)
	os.Exit(code)
}

func TestNewEngine(t *testing.T) {
	tests := []struct {
		name    string
		network string
		opts    []EngineOption
		wantErr bool
	}{
		{
			name:    "create with mainnet",
			network: "mainnet",
			opts:    nil,
			wantErr: false,
		},
		{
			name:    "create with testnet",
			network: "testnet",
			opts:    nil,
			wantErr: false,
		},
		{
			name:    "create with betanet",
			network: "betanet",
			opts:    nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng, err := NewEngine(tt.network, tt.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewEngine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if eng.Network != tt.network {
					t.Errorf("NewEngine() network = %v, want %v", eng.Network, tt.network)
				}
			}
		})
	}
}

func TestEngineWithOptions(t *testing.T) {
	// Test with alias cache
	aliasCache := cache.AliasCache{
		Aliases: map[string]string{"alice": "ABC123"},
	}

	eng, err := NewEngine("testnet", WithAliasCache(aliasCache))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	if eng.AliasCache.Aliases["alice"] != "ABC123" {
		t.Error("AliasCache not set correctly")
	}

	// Test with signer cache
	signerCache := cache.SignerCache{
		Keys: map[string]string{"ABC123": "ed25519"},
	}

	eng, err = NewEngine("testnet", WithSignerCache(signerCache))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	if eng.SignerCache.Keys["ABC123"] != "ed25519" {
		t.Error("SignerCache not set correctly")
	}

	// Test with set cache
	setCache := cache.SetCache{
		Sets: map[string][]string{"validators": {"ADDR1", "ADDR2"}},
	}

	eng, err = NewEngine("testnet", WithSetCache(setCache))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	if len(eng.SetCache.Sets["validators"]) != 2 {
		t.Error("SetCache not set correctly")
	}
}

func TestSetNetwork(t *testing.T) {
	eng, _ := NewEngine("testnet")

	tests := []struct {
		name    string
		network string
		wantErr bool
	}{
		{"switch to mainnet", "mainnet", false},
		{"switch to testnet", "testnet", false},
		{"switch to betanet", "betanet", false},
		{"switch to custom network", "voi_mainnet", false},
		{"invalid network", "InvalidNet", true},
		{"empty network", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := eng.SetNetwork(tt.network, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetNetwork() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && eng.Network != tt.network {
				t.Errorf("SetNetwork() network = %v, want %v", eng.Network, tt.network)
			}
		})
	}
}

func TestSetNetworkLoadsPerNetworkCachesWithoutBleedThrough(t *testing.T) {
	tmpDir := t.TempDir()
	store := cache.NewStore(tmpDir)

	testnetASACache := cache.LoadASACacheFromStore(store, "testnet")
	testnetASACache.Assets[999001] = cache.ASAInfo{Name: "Testnet Token", UnitName: "TST", Decimals: 3}
	if err := testnetASACache.SaveCache("testnet"); err != nil {
		t.Fatalf("failed to save testnet ASA cache: %v", err)
	}
	testnetAuthCache := cache.NewAuthAddressCacheForStore(store)
	testnetAuthCache.AuthAddresses["ADDR_TEST"] = "AUTH_TEST"
	if err := testnetAuthCache.SaveCache("testnet"); err != nil {
		t.Fatalf("failed to save testnet auth cache: %v", err)
	}

	mainnetASACache := cache.LoadASACacheFromStore(store, "mainnet")
	mainnetASACache.Assets[999002] = cache.ASAInfo{Name: "Mainnet Token", UnitName: "MNT", Decimals: 6}
	if err := mainnetASACache.SaveCache("mainnet"); err != nil {
		t.Fatalf("failed to save mainnet ASA cache: %v", err)
	}
	mainnetAuthCache := cache.NewAuthAddressCacheForStore(store)
	mainnetAuthCache.AuthAddresses["ADDR_MAIN"] = "AUTH_MAIN"
	if err := mainnetAuthCache.SaveCache("mainnet"); err != nil {
		t.Fatalf("failed to save mainnet auth cache: %v", err)
	}

	eng, err := NewEngine("testnet",
		WithCacheStore(store),
		WithASACache(cache.LoadASACacheFromStore(store, "testnet")),
		WithAuthCache(cache.LoadAuthCacheFromStore(store, "testnet")),
	)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	if _, ok := eng.AsaCache.Assets[999001]; !ok {
		t.Fatal("expected testnet-specific ASA cache entry at startup")
	}
	if _, ok := eng.AsaCache.Assets[999002]; ok {
		t.Fatal("unexpected mainnet ASA entry present in testnet cache")
	}
	if got, ok := eng.AuthCache.GetAuthAddress("ADDR_TEST"); !ok || got != "AUTH_TEST" {
		t.Fatalf("testnet auth cache = (%q, %v), want (AUTH_TEST, true)", got, ok)
	}
	if _, ok := eng.AuthCache.GetAuthAddress("ADDR_MAIN"); ok {
		t.Fatal("unexpected mainnet auth entry present in testnet cache")
	}

	if err := eng.SetNetwork("mainnet", nil); err != nil {
		t.Fatalf("SetNetwork(mainnet) error = %v", err)
	}
	if _, ok := eng.AsaCache.Assets[999002]; !ok {
		t.Fatal("expected mainnet-specific ASA cache entry after switch")
	}
	if _, ok := eng.AsaCache.Assets[999001]; ok {
		t.Fatal("unexpected testnet ASA entry present after switching to mainnet")
	}
	if got, ok := eng.AuthCache.GetAuthAddress("ADDR_MAIN"); !ok || got != "AUTH_MAIN" {
		t.Fatalf("mainnet auth cache = (%q, %v), want (AUTH_MAIN, true)", got, ok)
	}
	if _, ok := eng.AuthCache.GetAuthAddress("ADDR_TEST"); ok {
		t.Fatal("unexpected testnet auth entry present after switching to mainnet")
	}

	if err := eng.SetNetwork("testnet", nil); err != nil {
		t.Fatalf("SetNetwork(testnet) error = %v", err)
	}
	if _, ok := eng.AsaCache.Assets[999001]; !ok {
		t.Fatal("expected testnet-specific ASA cache entry after switching back")
	}
	if _, ok := eng.AsaCache.Assets[999002]; ok {
		t.Fatal("unexpected mainnet ASA entry present after switching back to testnet")
	}
	if got, ok := eng.AuthCache.GetAuthAddress("ADDR_TEST"); !ok || got != "AUTH_TEST" {
		t.Fatalf("reloaded testnet auth cache = (%q, %v), want (AUTH_TEST, true)", got, ok)
	}
	if _, ok := eng.AuthCache.GetAuthAddress("ADDR_MAIN"); ok {
		t.Fatal("unexpected mainnet auth entry present after switching back to testnet")
	}
}

func TestWriteMode(t *testing.T) {
	eng, _ := NewEngine("testnet")

	// Default should be false
	if eng.GetWriteMode() {
		t.Error("Default write mode should be false")
	}

	// Enable write mode
	eng.SetWriteMode(true)
	if !eng.GetWriteMode() {
		t.Error("Write mode should be true after SetWriteMode(true)")
	}

	// Disable write mode
	eng.SetWriteMode(false)
	if eng.GetWriteMode() {
		t.Error("Write mode should be false after SetWriteMode(false)")
	}
}

func TestGetNetwork(t *testing.T) {
	eng, _ := NewEngine("testnet")

	if eng.GetNetwork() != "testnet" {
		t.Errorf("GetNetwork() = %v, want testnet", eng.GetNetwork())
	}

	eng.Network = "mainnet"
	if eng.GetNetwork() != "mainnet" {
		t.Errorf("GetNetwork() = %v, want mainnet", eng.GetNetwork())
	}
}
