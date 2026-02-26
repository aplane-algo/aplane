// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestNewAuthAddressCache verifies creation of empty cache
func TestNewAuthAddressCache(t *testing.T) {
	cache := NewAuthAddressCache()

	if cache.AuthAddresses == nil {
		t.Fatal("AuthAddresses map should be initialized")
	}

	if len(cache.AuthAddresses) != 0 {
		t.Errorf("New cache should be empty, got %d entries", len(cache.AuthAddresses))
	}
}

// TestGetAuthCacheFilename verifies cache filename generation
func TestGetAuthCacheFilename(t *testing.T) {
	tests := []struct {
		network  string
		expected string
	}{
		{"mainnet", "cache/mainnet_auth_cache.json"},
		{"testnet", "cache/testnet_auth_cache.json"},
		{"betanet", "cache/betanet_auth_cache.json"},
		{"localnet", "cache/localnet_auth_cache.json"},
		{"custom-network", "cache/custom-network_auth_cache.json"},
	}

	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			filename := GetAuthCacheFilename(tt.network)
			if filename != tt.expected {
				t.Errorf("GetAuthCacheFilename(%q) = %q, want %q",
					tt.network, filename, tt.expected)
			}
		})
	}
}

// TestSaveAndLoadAuthCache verifies cache persistence
func TestSaveAndLoadAuthCache(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}

	network := "testnet"

	// Create cache with test data
	cache := NewAuthAddressCache()
	cache.AuthAddresses["ADDR1"] = "AUTH1"
	cache.AuthAddresses["ADDR2"] = ""
	cache.AuthAddresses["ADDR3"] = "AUTH3"

	// Save
	if err := cache.SaveCache(network); err != nil {
		t.Fatalf("SaveCache failed: %v", err)
	}

	// Verify file exists
	filename := GetAuthCacheFilename(network)
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		t.Fatal("Cache file was not created")
	}

	// Load
	loaded := LoadAuthCache(network)

	// Verify contents match
	if len(loaded.AuthAddresses) != len(cache.AuthAddresses) {
		t.Errorf("Loaded cache has %d entries, expected %d",
			len(loaded.AuthAddresses), len(cache.AuthAddresses))
	}

	for addr, authAddr := range cache.AuthAddresses {
		loadedAuthAddr, exists := loaded.AuthAddresses[addr]
		if !exists {
			t.Errorf("Address %s not found in loaded cache", addr)
			continue
		}
		if loadedAuthAddr != authAddr {
			t.Errorf("Address %s: auth = %q, want %q", addr, loadedAuthAddr, authAddr)
		}
	}
}

// TestLoadAuthCacheNonExistent verifies handling of missing cache file
func TestLoadAuthCacheNonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}

	// Load non-existent cache
	cache := LoadAuthCache("nonexistent-network")

	// Should return empty cache without error
	if cache.AuthAddresses == nil {
		t.Fatal("Loaded cache should have initialized map")
	}

	if len(cache.AuthAddresses) != 0 {
		t.Errorf("Non-existent cache should load as empty, got %d entries", len(cache.AuthAddresses))
	}
}

// TestSaveAuthCachePermissions verifies file permissions
func TestSaveAuthCachePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}

	cache := NewAuthAddressCache()
	cache.AuthAddresses["TEST"] = "AUTH"

	if err := cache.SaveCache("testnet"); err != nil {
		t.Fatalf("SaveCache failed: %v", err)
	}

	filename := GetAuthCacheFilename("testnet")
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatalf("Failed to stat cache file: %v", err)
	}

	// Verify 0660 permissions
	mode := info.Mode().Perm()
	expectedMode := os.FileMode(0660)
	if mode != expectedMode {
		t.Errorf("Cache file has permissions %o, want %o", mode, expectedMode)
	}
}

// TestGetAuthAddress verifies retrieval from cache
func TestGetAuthAddress(t *testing.T) {
	cache := NewAuthAddressCache()
	cache.AuthAddresses["REKEYED_ADDR"] = "AUTH_ADDR"
	cache.AuthAddresses["NORMAL_ADDR"] = ""

	tests := []struct {
		name         string
		address      string
		wantAuthAddr string
		wantExists   bool
	}{
		{
			name:         "rekeyed account",
			address:      "REKEYED_ADDR",
			wantAuthAddr: "AUTH_ADDR",
			wantExists:   true,
		},
		{
			name:         "normal account",
			address:      "NORMAL_ADDR",
			wantAuthAddr: "",
			wantExists:   true,
		},
		{
			name:         "not in cache",
			address:      "UNKNOWN_ADDR",
			wantAuthAddr: "",
			wantExists:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authAddr, exists := cache.GetAuthAddress(tt.address)

			if exists != tt.wantExists {
				t.Errorf("exists = %v, want %v", exists, tt.wantExists)
			}

			if authAddr != tt.wantAuthAddr {
				t.Errorf("authAddr = %q, want %q", authAddr, tt.wantAuthAddr)
			}
		})
	}
}

// TestUpdateAuthAddress verifies cache updates
func TestUpdateAuthAddress(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}

	cache := NewAuthAddressCache()
	network := "testnet"

	tests := []struct {
		name        string
		address     string
		authAddress string
		wantStored  string // What should be stored in cache
	}{
		{
			name:        "rekeyed account",
			address:     "ADDR1",
			authAddress: "AUTH1",
			wantStored:  "AUTH1",
		},
		{
			name:        "not rekeyed (empty)",
			address:     "ADDR2",
			authAddress: "",
			wantStored:  "",
		},
		{
			name:        "not rekeyed (same address)",
			address:     "ADDR3",
			authAddress: "ADDR3",
			wantStored:  "", // Should normalize to empty
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cache.UpdateAuthAddress(tt.address, tt.authAddress, network)
			if err != nil {
				t.Fatalf("UpdateAuthAddress failed: %v", err)
			}

			// Verify in-memory cache
			stored, exists := cache.AuthAddresses[tt.address]
			if !exists {
				t.Fatal("Address not found in cache after update")
			}

			if stored != tt.wantStored {
				t.Errorf("Stored auth address = %q, want %q", stored, tt.wantStored)
			}

			// Verify persistence
			loaded := LoadAuthCache(network)
			loadedAuth, exists := loaded.AuthAddresses[tt.address]
			if !exists {
				t.Error("Address not found in loaded cache")
			}

			if loadedAuth != tt.wantStored {
				t.Errorf("Loaded auth address = %q, want %q", loadedAuth, tt.wantStored)
			}
		})
	}
}

// TestUpdateAuthAddressOverwrite verifies updating existing entries
func TestUpdateAuthAddressOverwrite(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}

	cache := NewAuthAddressCache()
	network := "testnet"
	address := "TEST_ADDR"

	// Initial value
	_ = cache.UpdateAuthAddress(address, "AUTH1", network)

	stored := cache.AuthAddresses[address]
	if stored != "AUTH1" {
		t.Fatalf("Initial update failed")
	}

	// Update to new auth address
	_ = cache.UpdateAuthAddress(address, "AUTH2", network)

	stored = cache.AuthAddresses[address]
	if stored != "AUTH2" {
		t.Errorf("Auth address = %q, want AUTH2", stored)
	}

	// Update to empty (un-rekey)
	_ = cache.UpdateAuthAddress(address, "", network)

	stored = cache.AuthAddresses[address]
	if stored != "" {
		t.Errorf("Auth address = %q, want empty", stored)
	}
}

// TestAuthCacheConcurrentReads verifies concurrent read operations
func TestAuthCacheConcurrentReads(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}

	cache := NewAuthAddressCache()
	cache.AuthAddresses["ADDR1"] = "AUTH1"
	cache.AuthAddresses["ADDR2"] = ""
	network := "testnet"

	// Save initial cache
	_ = cache.SaveCache(network)

	concurrency := 50
	done := make(chan bool, concurrency)

	// Concurrent reads are safe
	for i := 0; i < concurrency; i++ {
		go func() {
			// Read from cache
			_, _ = cache.GetAuthAddress("ADDR1")
			_, _ = cache.GetAuthAddress("ADDR2")

			// Load from disk (creates new instance)
			loaded := LoadAuthCache(network)
			_, _ = loaded.GetAuthAddress("ADDR1")

			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < concurrency; i++ {
		<-done
	}

	// Verify cache is still valid
	if cache.AuthAddresses == nil {
		t.Error("Cache map should still be initialized")
	}
}

// TestAuthCacheDirectoryCreation verifies cache directory is auto-created
func TestAuthCacheDirectoryCreation(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}

	// Ensure cache directory doesn't exist
	_ = os.RemoveAll("cache")

	cache := NewAuthAddressCache()
	cache.AuthAddresses["TEST"] = "AUTH"

	if err := cache.SaveCache("testnet"); err != nil {
		t.Fatalf("SaveCache failed: %v", err)
	}

	// Verify directory was created
	info, err := os.Stat("cache")
	if err != nil {
		t.Fatalf("Cache directory was not created: %v", err)
	}

	if !info.IsDir() {
		t.Error("cache should be a directory")
	}

	// Verify permissions (0770)
	mode := info.Mode().Perm()
	expectedMode := os.FileMode(0770)
	if mode != expectedMode {
		t.Errorf("Cache directory has permissions %o, want %o", mode, expectedMode)
	}
}

// TestAuthCacheJSONFormat verifies signed cache JSON structure
func TestAuthCacheJSONFormat(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}

	cache := NewAuthAddressCache()
	cache.AuthAddresses["ADDR1"] = "AUTH1"
	cache.AuthAddresses["ADDR2"] = ""

	network := "testnet"
	if err := cache.SaveCache(network); err != nil {
		t.Fatalf("SaveCache failed: %v", err)
	}

	// Read raw JSON
	filename := GetAuthCacheFilename(network)
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read cache file: %v", err)
	}

	// Verify it's valid signed cache JSON structure
	var rawCache map[string]interface{}
	if err := json.Unmarshal(data, &rawCache); err != nil {
		t.Fatalf("Cache file is not valid JSON: %v", err)
	}

	// Verify signed cache structure (version, data, hmac)
	if _, exists := rawCache["version"]; !exists {
		t.Error("JSON should have 'version' field")
	}
	if _, exists := rawCache["data"]; !exists {
		t.Error("JSON should have 'data' field")
	}
	if _, exists := rawCache["hmac"]; !exists {
		t.Error("JSON should have 'hmac' field")
	}
}

// TestLoadAuthCacheInvalidJSON verifies handling of corrupted cache
func TestLoadAuthCacheInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}

	// Create cache directory
	_ = os.MkdirAll("cache", 0750)

	// Write invalid JSON
	network := "testnet"
	filename := GetAuthCacheFilename(network)
	_ = os.WriteFile(filename, []byte("{invalid json"), 0600)

	// Should return empty cache without crashing
	cache := LoadAuthCache(network)

	if cache.AuthAddresses == nil {
		t.Fatal("Cache should have initialized map even with invalid JSON")
	}

	// May be empty or may have partial data - just verify no crash
	_ = len(cache.AuthAddresses)
}

// TestBuildAuthCacheNilClient verifies handling of nil algod client
func TestBuildAuthCacheNilClient(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}

	aliasCache := &AliasCache{
		Aliases: map[string]string{"alice": "ALICE_ADDR"},
	}

	signerCache := &SignerCache{
		Keys: map[string]string{"SIGNER_ADDR": "ed25519"},
	}

	// Should not crash with nil client
	cache := BuildAuthCache(nil, aliasCache, signerCache, "testnet")

	if cache.AuthAddresses == nil {
		t.Fatal("Cache should be initialized")
	}

	// Without client, should return empty cache
	if len(cache.AuthAddresses) != 0 {
		t.Error("Cache should be empty when client is nil")
	}
}

// TestBuildAuthCacheEmptyInputs verifies handling of empty alias/signer caches
func TestBuildAuthCacheEmptyInputs(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}

	emptyAliasCache := &AliasCache{
		Aliases: map[string]string{},
	}

	emptySignerCache := &SignerCache{
		Keys: map[string]string{},
	}

	// Should handle empty inputs gracefully
	cache := BuildAuthCache(nil, emptyAliasCache, emptySignerCache, "testnet")

	if cache.AuthAddresses == nil {
		t.Fatal("Cache should be initialized")
	}
}

// TestAuthCacheFileLocation verifies cache files are in cache/ subdirectory
func TestAuthCacheFileLocation(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}

	cache := NewAuthAddressCache()
	cache.AuthAddresses["TEST"] = "AUTH"

	network := "testnet"
	_ = cache.SaveCache(network)

	// Verify file is in cache/ subdirectory
	expectedPath := filepath.Join("cache", network+"_auth_cache.json")
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Errorf("Cache file not found at expected path: %s", expectedPath)
	}

	// Verify it's not in root directory
	rootPath := network + "_auth_cache.json"
	if _, err := os.Stat(rootPath); err == nil {
		t.Error("Cache file should not be in root directory")
	}
}

// TestResolveEffectiveSigner verifies effective signer resolution
func TestResolveEffectiveSigner(t *testing.T) {
	cache := NewAuthAddressCache()
	cache.AuthAddresses["REKEYED_ADDR"] = "AUTH_ADDR"
	cache.AuthAddresses["NORMAL_ADDR"] = ""

	tests := []struct {
		name     string
		cache    *AuthAddressCache
		sender   string
		expected string
	}{
		{
			name:     "rekeyed account returns auth address",
			cache:    &cache,
			sender:   "REKEYED_ADDR",
			expected: "AUTH_ADDR",
		},
		{
			name:     "normal account returns sender",
			cache:    &cache,
			sender:   "NORMAL_ADDR",
			expected: "NORMAL_ADDR",
		},
		{
			name:     "unknown account returns sender",
			cache:    &cache,
			sender:   "UNKNOWN_ADDR",
			expected: "UNKNOWN_ADDR",
		},
		{
			name:     "nil cache returns sender",
			cache:    nil,
			sender:   "ANY_ADDR",
			expected: "ANY_ADDR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.cache.ResolveEffectiveSigner(tt.sender)
			if result != tt.expected {
				t.Errorf("ResolveEffectiveSigner(%q) = %q, want %q",
					tt.sender, result, tt.expected)
			}
		})
	}
}
