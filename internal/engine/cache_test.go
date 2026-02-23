// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/util"
)

// setupTestEngine creates an engine with in-memory caches for testing
func setupTestEngine(t *testing.T) *Engine {
	t.Helper()

	// Create temp directory for cache files
	tmpDir, err := os.MkdirTemp("", "engine-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	// Create cache subdirectory
	cacheDir := filepath.Join(tmpDir, "cache")
	if err := os.MkdirAll(cacheDir, 0750); err != nil {
		t.Fatalf("Failed to create cache dir: %v", err)
	}

	// Change to temp directory so cache files are created there
	origDir, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	eng, err := NewEngine("testnet",
		WithAliasCache(util.AliasCache{Aliases: make(map[string]string)}),
		WithSetCache(util.SetCache{Sets: make(map[string][]string)}),
		WithSignerCache(util.SignerCache{Keys: make(map[string]string)}),
		WithAuthCache(util.AuthAddressCache{AuthAddresses: make(map[string]string)}),
	)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	return eng
}

func TestListAliases(t *testing.T) {
	eng := setupTestEngine(t)

	// Empty list
	result := eng.ListAliases()
	if len(result.Aliases) != 0 {
		t.Errorf("Expected 0 aliases, got %d", len(result.Aliases))
	}

	// Add some aliases
	eng.AliasCache.Aliases["alice"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	eng.AliasCache.Aliases["bob"] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

	result = eng.ListAliases()
	if len(result.Aliases) != 2 {
		t.Errorf("Expected 2 aliases, got %d", len(result.Aliases))
	}

	// Check sorted order (alice before bob)
	if result.Aliases[0].Name != "alice" {
		t.Errorf("Expected first alias to be 'alice', got '%s'", result.Aliases[0].Name)
	}
	if result.Aliases[1].Name != "bob" {
		t.Errorf("Expected second alias to be 'bob', got '%s'", result.Aliases[1].Name)
	}
}

func TestGetAlias(t *testing.T) {
	eng := setupTestEngine(t)

	// Non-existent alias
	alias := eng.GetAlias("alice")
	if alias != nil {
		t.Error("Expected nil for non-existent alias")
	}

	// Add alias
	testAddr := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	eng.AliasCache.Aliases["alice"] = testAddr

	alias = eng.GetAlias("alice")
	if alias == nil {
		t.Fatal("Expected alias, got nil")
	}
	if alias.Name != "alice" {
		t.Errorf("Expected name 'alice', got '%s'", alias.Name)
	}
	if alias.Address != testAddr {
		t.Errorf("Expected address %s, got %s", testAddr, alias.Address)
	}
}

func TestAddAlias(t *testing.T) {
	eng := setupTestEngine(t)

	// Valid address (using well-known test address pattern)
	validAddr := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"

	tests := []struct {
		name       string
		aliasName  string
		address    string
		wantErr    bool
		wantUpdate bool
	}{
		{
			name:      "add new alias",
			aliasName: "alice",
			address:   validAddr,
			wantErr:   false,
		},
		{
			name:      "invalid address",
			aliasName: "bob",
			address:   "invalid",
			wantErr:   true,
		},
		{
			name:      "short address",
			aliasName: "charlie",
			address:   "ABC123",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := eng.AddAlias(tt.aliasName, tt.address)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddAlias() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if result.Name != tt.aliasName {
					t.Errorf("AddAlias() name = %v, want %v", result.Name, tt.aliasName)
				}
				if result.Address != tt.address {
					t.Errorf("AddAlias() address = %v, want %v", result.Address, tt.address)
				}
			}
		})
	}
}

func TestAddAliasUpdate(t *testing.T) {
	eng := setupTestEngine(t)

	// Both addresses must have valid checksums (generated from SDK)
	addr1 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	addr2 := "7777777777777777777777777777777777777777777777777774MSJUVU"

	// Add initial alias
	result1, err := eng.AddAlias("alice", addr1)
	if err != nil {
		t.Fatalf("First AddAlias() error = %v", err)
	}
	if result1.WasUpdated {
		t.Error("First AddAlias() should not be an update")
	}

	// Update alias
	result2, err := eng.AddAlias("alice", addr2)
	if err != nil {
		t.Fatalf("Second AddAlias() error = %v", err)
	}
	if !result2.WasUpdated {
		t.Error("Second AddAlias() should be an update")
	}
	if result2.OldAddress != addr1 {
		t.Errorf("OldAddress = %v, want %v", result2.OldAddress, addr1)
	}

	// Same address again - no update
	result3, err := eng.AddAlias("alice", addr2)
	if err != nil {
		t.Fatalf("Third AddAlias() error = %v", err)
	}
	if result3.WasUpdated {
		t.Error("Third AddAlias() should not be an update (same address)")
	}
}

func TestRemoveAlias(t *testing.T) {
	eng := setupTestEngine(t)

	// Remove non-existent alias
	_, err := eng.RemoveAlias("alice")
	if err == nil {
		t.Error("Expected error removing non-existent alias")
	}

	// Add then remove
	testAddr := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	eng.AliasCache.Aliases["alice"] = testAddr

	addr, err := eng.RemoveAlias("alice")
	if err != nil {
		t.Errorf("RemoveAlias() error = %v", err)
	}
	if addr != testAddr {
		t.Errorf("RemoveAlias() returned %v, want %v", addr, testAddr)
	}

	// Verify removed
	if _, exists := eng.AliasCache.Aliases["alice"]; exists {
		t.Error("Alias should be removed from cache")
	}
}

func TestListSets(t *testing.T) {
	eng := setupTestEngine(t)

	// Empty list
	result := eng.ListSets()
	if len(result.Sets) != 0 {
		t.Errorf("Expected 0 sets, got %d", len(result.Sets))
	}

	// Add some sets
	eng.SetCache.Sets["validators"] = []string{"ADDR1", "ADDR2"}
	eng.SetCache.Sets["admins"] = []string{"ADDR3"}

	result = eng.ListSets()
	if len(result.Sets) != 2 {
		t.Errorf("Expected 2 sets, got %d", len(result.Sets))
	}

	// Check sorted order (admins before validators)
	if result.Sets[0].Name != "admins" {
		t.Errorf("Expected first set to be 'admins', got '%s'", result.Sets[0].Name)
	}
	if result.Sets[0].Count != 1 {
		t.Errorf("Expected admins count 1, got %d", result.Sets[0].Count)
	}
}

func TestGetSet(t *testing.T) {
	eng := setupTestEngine(t)

	// Non-existent set
	set := eng.GetSet("validators")
	if set != nil {
		t.Error("Expected nil for non-existent set")
	}

	// Add set
	eng.SetCache.Sets["validators"] = []string{"ADDR1", "ADDR2", "ADDR3"}

	set = eng.GetSet("validators")
	if set == nil {
		t.Fatal("Expected set, got nil")
	}
	if set.Name != "validators" {
		t.Errorf("Expected name 'validators', got '%s'", set.Name)
	}
	if set.Count != 3 {
		t.Errorf("Expected count 3, got %d", set.Count)
	}

	// Test with @ prefix
	set = eng.GetSet("@validators")
	if set == nil {
		t.Fatal("Expected set with @ prefix, got nil")
	}
	if set.Name != "validators" {
		t.Errorf("Expected name 'validators' (@ stripped), got '%s'", set.Name)
	}
}

func TestAddSet(t *testing.T) {
	eng := setupTestEngine(t)

	// Add valid addresses directly (bypass resolution for unit test)
	eng.AliasCache.Aliases["alice"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	eng.AliasCache.Aliases["bob"] = "7777777777777777777777777777777777777777777777777774MSJUVU"

	result, err := eng.AddSet("team", []string{"alice", "bob"})
	if err != nil {
		t.Fatalf("AddSet() error = %v", err)
	}

	if result.Name != "team" {
		t.Errorf("AddSet() name = %v, want 'team'", result.Name)
	}
	if len(result.Addresses) != 2 {
		t.Errorf("AddSet() addresses count = %v, want 2", len(result.Addresses))
	}
	if result.WasUpdated {
		t.Error("AddSet() should not be an update for new set")
	}
}

func TestAddSetWithPrefix(t *testing.T) {
	eng := setupTestEngine(t)

	eng.AliasCache.Aliases["alice"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"

	// Add set with @ prefix - should strip it
	result, err := eng.AddSet("@team", []string{"alice"})
	if err != nil {
		t.Fatalf("AddSet() error = %v", err)
	}

	if result.Name != "team" {
		t.Errorf("AddSet() should strip @ prefix, got name = '%s'", result.Name)
	}
}

func TestRemoveSet(t *testing.T) {
	eng := setupTestEngine(t)

	// Remove non-existent set
	_, err := eng.RemoveSet("validators")
	if err == nil {
		t.Error("Expected error removing non-existent set")
	}

	// Add then remove
	eng.SetCache.Sets["validators"] = []string{"ADDR1", "ADDR2"}

	count, err := eng.RemoveSet("validators")
	if err != nil {
		t.Errorf("RemoveSet() error = %v", err)
	}
	if count != 2 {
		t.Errorf("RemoveSet() count = %v, want 2", count)
	}

	// Verify removed
	if _, exists := eng.SetCache.Sets["validators"]; exists {
		t.Error("Set should be removed from cache")
	}

	// Test with @ prefix
	eng.SetCache.Sets["admins"] = []string{"ADDR3"}
	count, err = eng.RemoveSet("@admins")
	if err != nil {
		t.Errorf("RemoveSet(@admins) error = %v", err)
	}
	if count != 1 {
		t.Errorf("RemoveSet(@admins) count = %v, want 1", count)
	}
}

func TestAddToSet(t *testing.T) {
	eng := setupTestEngine(t)

	eng.AliasCache.Aliases["alice"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	eng.AliasCache.Aliases["bob"] = "7777777777777777777777777777777777777777777777777774MSJUVU"
	eng.AliasCache.Aliases["charlie"] = "CHARLIECHARLIECHARLIECHARLIECHARLIECHARLIECHARLIEY5HFKQ"

	// Add to new set
	result1, err := eng.AddToSet("team", []string{"alice"})
	if err != nil {
		t.Fatalf("AddToSet() error = %v", err)
	}
	if len(result1.Addresses) != 1 {
		t.Errorf("AddToSet() addresses = %d, want 1", len(result1.Addresses))
	}

	// Add more to existing set
	result2, err := eng.AddToSet("team", []string{"bob", "charlie"})
	if err != nil {
		t.Fatalf("AddToSet() error = %v", err)
	}
	if len(result2.Addresses) != 3 {
		t.Errorf("AddToSet() addresses = %d, want 3", len(result2.Addresses))
	}
	if !result2.WasUpdated {
		t.Error("AddToSet() should be an update")
	}
	if result2.OldCount != 1 {
		t.Errorf("AddToSet() OldCount = %d, want 1", result2.OldCount)
	}
}

func TestAddToSetDeduplication(t *testing.T) {
	eng := setupTestEngine(t)

	addr := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	eng.AliasCache.Aliases["alice"] = addr

	// Add alice twice
	_, _ = eng.AddToSet("team", []string{"alice"})
	result, err := eng.AddToSet("team", []string{"alice"})
	if err != nil {
		t.Fatalf("AddToSet() error = %v", err)
	}

	// Should still only have 1 address (deduplicated)
	if len(result.Addresses) != 1 {
		t.Errorf("AddToSet() should deduplicate, got %d addresses", len(result.Addresses))
	}
}

func TestRemoveFromSet(t *testing.T) {
	eng := setupTestEngine(t)

	addr1 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	addr2 := "7777777777777777777777777777777777777777777777777774MSJUVU"

	eng.AliasCache.Aliases["alice"] = addr1
	eng.AliasCache.Aliases["bob"] = addr2

	// Setup set with both addresses
	eng.SetCache.Sets["team"] = []string{addr1, addr2}

	// Remove one
	result, err := eng.RemoveFromSet("team", []string{"alice"})
	if err != nil {
		t.Fatalf("RemoveFromSet() error = %v", err)
	}

	if len(result.Addresses) != 1 {
		t.Errorf("RemoveFromSet() addresses = %d, want 1", len(result.Addresses))
	}
	if result.OldCount != 2 {
		t.Errorf("RemoveFromSet() OldCount = %d, want 2", result.OldCount)
	}
}

func TestRemoveFromSetNonExistent(t *testing.T) {
	eng := setupTestEngine(t)

	_, err := eng.RemoveFromSet("nonexistent", []string{"alice"})
	if err == nil {
		t.Error("Expected error removing from non-existent set")
	}
}
