// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/signerapi"
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
		WithAliasCache(cache.AliasCache{Aliases: make(map[string]string)}),
		WithSetCache(cache.SetCache{Sets: make(map[string][]string)}),
		WithSignerCache(cache.SignerCache{Keys: make(map[string]string)}),
		WithAuthCache(cache.AuthAddressCache{AuthAddresses: make(map[string]string)}),
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
	switch {
	case alias == nil:
		t.Fatal("Expected alias, got nil")
	case alias.Name != "alice":
		t.Errorf("Expected name 'alice', got '%s'", alias.Name)
	case alias.Address != testAddr:
		t.Errorf("Expected address %s, got %s", testAddr, alias.Address)
	}
}

func TestAddAlias(t *testing.T) {
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
			name:      "normalizes alias name",
			aliasName: "Alice_One",
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
		{
			name:      "invalid alias name punctuation",
			aliasName: "alice.team",
			address:   validAddr,
			wantErr:   true,
		},
		{
			name:      "reserved alias name",
			aliasName: "list",
			address:   validAddr,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := setupTestEngine(t)
			result, err := eng.AddAliasWithContext(context.Background(), tt.aliasName, tt.address)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddAlias() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				wantName := strings.ToLower(tt.aliasName)
				if result.Name != wantName {
					t.Errorf("AddAlias() name = %v, want %v", result.Name, wantName)
				}
				if result.Address != tt.address {
					t.Errorf("AddAlias() address = %v, want %v", result.Address, tt.address)
				}
			}
		})
	}
}

func TestAliasLookupsNormalizeName(t *testing.T) {
	eng := setupTestEngine(t)
	addr := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"

	result, err := eng.AddAliasWithContext(context.Background(), "HELLO", addr)
	if err != nil {
		t.Fatalf("AddAliasWithContext() error = %v", err)
	}
	if result.Name != "hello" {
		t.Fatalf("result.Name = %q, want hello", result.Name)
	}
	if _, exists := eng.AliasCache.Aliases["HELLO"]; exists {
		t.Fatal("alias stored with uppercase key, want lowercase only")
	}
	if got := eng.GetAlias("HELLO"); got == nil || got.Name != "hello" {
		t.Fatalf("GetAlias(HELLO) = %#v, want lowercase alias", got)
	}
	resolved, _, err := eng.ResolveAddress("HELLO")
	if err != nil {
		t.Fatalf("ResolveAddress(HELLO) error = %v", err)
	}
	if resolved != addr {
		t.Fatalf("ResolveAddress(HELLO) = %q, want %q", resolved, addr)
	}
}

func TestAddAliasUpdate(t *testing.T) {
	eng := setupTestEngine(t)

	// Both addresses must have valid checksums (generated from SDK)
	addr1 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	addr2 := "7777777777777777777777777777777777777777777777777774MSJUVU"

	// Add initial alias
	result1, err := eng.AddAliasWithContext(context.Background(), "alice", addr1)
	if err != nil {
		t.Fatalf("First AddAlias() error = %v", err)
	}
	if result1.WasUpdated {
		t.Error("First AddAlias() should not be an update")
	}

	// Update alias
	result2, err := eng.AddAliasWithContext(context.Background(), "alice", addr2)
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
	result3, err := eng.AddAliasWithContext(context.Background(), "alice", addr2)
	if err != nil {
		t.Fatalf("Third AddAlias() error = %v", err)
	}
	if result3.WasUpdated {
		t.Error("Third AddAlias() should not be an update (same address)")
	}
}

func TestAddAliasResultMatchesSubsequentCacheBackedViews(t *testing.T) {
	eng := setupTestEngine(t)

	addr := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	eng.SignerCache.Keys[addr] = "ed25519"
	eng.AuthCache.AuthAddresses[addr] = ""

	result, err := eng.AddAliasWithContext(context.Background(), "alice", addr)
	if err != nil {
		t.Fatalf("AddAlias() error = %v", err)
	}
	if result.Name != "alice" {
		t.Fatalf("result.Name = %q, want alice", result.Name)
	}
	if result.Address != addr {
		t.Fatalf("result.Address = %q, want %q", result.Address, addr)
	}
	if !result.IsSignable {
		t.Fatal("result.IsSignable = false, want true")
	}
	if result.KeyType != "ed25519" {
		t.Fatalf("result.KeyType = %q, want ed25519", result.KeyType)
	}

	aliases := eng.ListAliases()
	if len(aliases.Aliases) != 1 {
		t.Fatalf("len(ListAliases().Aliases) = %d, want 1", len(aliases.Aliases))
	}
	if aliases.Aliases[0].Name != result.Name {
		t.Fatalf("listed alias name = %q, want %q", aliases.Aliases[0].Name, result.Name)
	}
	if aliases.Aliases[0].Address != result.Address {
		t.Fatalf("listed alias address = %q, want %q", aliases.Aliases[0].Address, result.Address)
	}

	accounts, err := eng.ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts() error = %v", err)
	}
	if len(accounts) != 1 {
		t.Fatalf("len(ListAccounts()) = %d, want 1", len(accounts))
	}
	if accounts[0].Alias != result.Name {
		t.Fatalf("account alias = %q, want %q", accounts[0].Alias, result.Name)
	}
	if accounts[0].Address != result.Address {
		t.Fatalf("account address = %q, want %q", accounts[0].Address, result.Address)
	}
	if !accounts[0].IsSignable {
		t.Fatal("account IsSignable = false, want true")
	}
	if accounts[0].KeyType != result.KeyType {
		t.Fatalf("account key type = %q, want %q", accounts[0].KeyType, result.KeyType)
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
	switch {
	case set == nil:
		t.Fatal("Expected set, got nil")
	case set.Name != "validators":
		t.Errorf("Expected name 'validators', got '%s'", set.Name)
	case set.Count != 3:
		t.Errorf("Expected count 3, got %d", set.Count)
	}

	// Test with @ prefix
	set = eng.GetSet("@validators")
	switch {
	case set == nil:
		t.Fatal("Expected set with @ prefix, got nil")
	case set.Name != "validators":
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

func TestAddSetRejectsInvalidName(t *testing.T) {
	eng := setupTestEngine(t)
	eng.AliasCache.Aliases["alice"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"

	tests := []string{"team.alpha", "team/alpha", "team alpha", "list", "add", "all", "signers"}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := eng.AddSet(name, []string{"alice"}); err == nil {
				t.Fatal("AddSet() error = nil, want invalid set name error")
			}
		})
	}
}

func TestSetNamesNormalize(t *testing.T) {
	eng := setupTestEngine(t)
	eng.AliasCache.Aliases["alice"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"

	result, err := eng.AddSet("TEAM_ONE", []string{"alice"})
	if err != nil {
		t.Fatalf("AddSet() error = %v", err)
	}
	if result.Name != "team_one" {
		t.Fatalf("AddSet() name = %q, want team_one", result.Name)
	}
	if _, exists := eng.SetCache.Sets["TEAM_ONE"]; exists {
		t.Fatal("set stored with uppercase key, want lowercase only")
	}
	if got := eng.GetSet("@TEAM_ONE"); got == nil || got.Name != "team_one" {
		t.Fatalf("GetSet(@TEAM_ONE) = %#v, want lowercase set", got)
	}
	resolved, err := eng.NewAddressResolver().ResolveList([]string{"@TEAM_ONE"})
	if err != nil {
		t.Fatalf("ResolveList(@TEAM_ONE) error = %v", err)
	}
	if len(resolved) != 1 || resolved[0] != eng.AliasCache.Aliases["alice"] {
		t.Fatalf("ResolveList(@TEAM_ONE) = %#v, want alice address", resolved)
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

func TestAddAliasPreservesConcurrentDiskUpdates(t *testing.T) {
	tmpDir := t.TempDir()
	cacheStore := cache.NewStore(tmpDir)

	newEngine := func() *Engine {
		eng, err := NewEngine("testnet",
			WithDataDir(tmpDir),
			WithCacheStore(cacheStore),
			WithAliasCache(cache.LoadAliasCacheFromStore(cacheStore)),
			WithSetCache(cache.LoadSetCacheFromStore(cacheStore)),
			WithSignerCache(cache.SignerCache{Keys: make(map[string]string)}),
			WithAuthCache(cache.NewAuthAddressCacheForStore(cacheStore)),
		)
		if err != nil {
			t.Fatalf("NewEngine() error = %v", err)
		}
		return eng
	}

	eng1 := newEngine()
	eng2 := newEngine() // Deliberately stale snapshot of the same on-disk state

	addr1 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	addr2 := "7777777777777777777777777777777777777777777777777774MSJUVU"

	if _, err := eng1.AddAliasWithContext(context.Background(), "alice", addr1); err != nil {
		t.Fatalf("eng1.AddAliasWithContext() error = %v", err)
	}
	if _, err := eng2.AddAliasWithContext(context.Background(), "bob", addr2); err != nil {
		t.Fatalf("eng2.AddAliasWithContext() error = %v", err)
	}

	merged := cache.LoadAliasCacheFromStore(cacheStore)
	if got := merged.Aliases["alice"]; got != addr1 {
		t.Fatalf("alias alice = %q, want %q", got, addr1)
	}
	if got := merged.Aliases["bob"]; got != addr2 {
		t.Fatalf("alias bob = %q, want %q", got, addr2)
	}
}

func TestInterleavedAliasAndSetWritesPreserveSharedStoreState(t *testing.T) {
	tmpDir := t.TempDir()
	cacheStore := cache.NewStore(tmpDir)

	newEngine := func() *Engine {
		eng, err := NewEngine("testnet",
			WithDataDir(tmpDir),
			WithCacheStore(cacheStore),
			WithAliasCache(cache.LoadAliasCacheFromStore(cacheStore)),
			WithSetCache(cache.LoadSetCacheFromStore(cacheStore)),
			WithSignerCache(cache.SignerCache{Keys: make(map[string]string)}),
			WithAuthCache(cache.NewAuthAddressCacheForStore(cacheStore)),
		)
		if err != nil {
			t.Fatalf("NewEngine() error = %v", err)
		}
		return eng
	}

	eng1 := newEngine()
	eng2 := newEngine() // stale snapshot over the same on-disk store

	addr1 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	addr2 := "7777777777777777777777777777777777777777777777777774MSJUVU"

	if _, err := eng1.AddAliasWithContext(context.Background(), "alice", addr1); err != nil {
		t.Fatalf("eng1.AddAliasWithContext() error = %v", err)
	}
	if _, err := eng2.AddToSet("team", []string{addr2}); err != nil {
		t.Fatalf("eng2.AddToSet() error = %v", err)
	}

	reloaded := newEngine()
	if got := reloaded.AliasCache.Aliases["alice"]; got != addr1 {
		t.Fatalf("reloaded alias alice = %q, want %q", got, addr1)
	}
	if got := reloaded.SetCache.Sets["team"]; !reflect.DeepEqual(got, []string{addr2}) {
		t.Fatalf("reloaded set team = %#v, want [%q]", got, addr2)
	}

	aliasResult := reloaded.ListAliases()
	if len(aliasResult.Aliases) != 1 || aliasResult.Aliases[0].Name != "alice" || aliasResult.Aliases[0].Address != addr1 {
		t.Fatalf("ListAliases() = %#v, want alice/%s", aliasResult.Aliases, addr1)
	}

	setResult := reloaded.ListSets()
	if len(setResult.Sets) != 1 || setResult.Sets[0].Name != "team" || !reflect.DeepEqual(setResult.Sets[0].Addresses, []string{addr2}) {
		t.Fatalf("ListSets() = %#v, want team with %q", setResult.Sets, addr2)
	}
}

func TestMultipleEnginesConvergeOnSharedStoreAfterReload(t *testing.T) {
	tmpDir := t.TempDir()
	cacheStore := cache.NewStore(tmpDir)

	newEngine := func() *Engine {
		eng, err := NewEngine("testnet",
			WithDataDir(tmpDir),
			WithCacheStore(cacheStore),
			WithAliasCache(cache.LoadAliasCacheFromStore(cacheStore)),
			WithSetCache(cache.LoadSetCacheFromStore(cacheStore)),
			WithSignerCache(cache.SignerCache{Keys: make(map[string]string)}),
			WithAuthCache(cache.NewAuthAddressCacheForStore(cacheStore)),
		)
		if err != nil {
			t.Fatalf("NewEngine() error = %v", err)
		}
		return eng
	}

	addr1 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	addr2 := "7777777777777777777777777777777777777777777777777774MSJUVU"

	eng1 := newEngine()
	if _, err := eng1.AddAliasWithContext(context.Background(), "alice", addr1); err != nil {
		t.Fatalf("eng1.AddAliasWithContext(alice) error = %v", err)
	}
	if _, err := eng1.AddAliasWithContext(context.Background(), "bob", addr2); err != nil {
		t.Fatalf("eng1.AddAliasWithContext(bob) error = %v", err)
	}

	eng2 := newEngine()
	if got := eng2.AliasCache.Aliases["alice"]; got != addr1 {
		t.Fatalf("eng2 alias alice = %q, want %q", got, addr1)
	}
	if got := eng2.AliasCache.Aliases["bob"]; got != addr2 {
		t.Fatalf("eng2 alias bob = %q, want %q", got, addr2)
	}
	if _, err := eng2.AddToSet("team", []string{"alice", "bob"}); err != nil {
		t.Fatalf("eng2.AddToSet() error = %v", err)
	}

	eng1Reloaded := newEngine()
	if got := eng1Reloaded.AliasCache.Aliases["alice"]; got != addr1 {
		t.Fatalf("eng1Reloaded alias alice = %q, want %q", got, addr1)
	}
	if got := eng1Reloaded.AliasCache.Aliases["bob"]; got != addr2 {
		t.Fatalf("eng1Reloaded alias bob = %q, want %q", got, addr2)
	}
	wantSet := []string{addr1, addr2}
	if got := eng1Reloaded.SetCache.Sets["team"]; !sameStrings(got, wantSet) {
		t.Fatalf("eng1Reloaded set team = %#v, want members %#v", got, wantSet)
	}

	eng2Reloaded := newEngine()
	if got := eng2Reloaded.SetCache.Sets["team"]; !sameStrings(got, wantSet) {
		t.Fatalf("eng2Reloaded set team = %#v, want members %#v", got, wantSet)
	}
	if got := eng2Reloaded.AliasCache.Aliases["alice"]; got != addr1 {
		t.Fatalf("eng2Reloaded alias alice = %q, want %q", got, addr1)
	}
	if got := eng2Reloaded.AliasCache.Aliases["bob"]; got != addr2 {
		t.Fatalf("eng2Reloaded alias bob = %q, want %q", got, addr2)
	}
}

func TestReconnectReplacesStaleSignerCacheWithFreshInventory(t *testing.T) {
	tmpDir := t.TempDir()
	cacheStore := cache.NewStore(tmpDir)

	newEngine := func() *Engine {
		eng, err := NewEngine("testnet",
			WithDataDir(tmpDir),
			WithCacheStore(cacheStore),
			WithAliasCache(cache.LoadAliasCacheFromStore(cacheStore)),
			WithSetCache(cache.LoadSetCacheFromStore(cacheStore)),
			WithSignerCache(cache.LoadSignerCacheFromStore(cacheStore)),
			WithAuthCache(cache.NewAuthAddressCacheForStore(cacheStore)),
		)
		if err != nil {
			t.Fatalf("NewEngine() error = %v", err)
		}
		return eng
	}

	staleAddr := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	freshAddr := "7777777777777777777777777777777777777777777777777774MSJUVU"

	eng := newEngine()
	eng.SignerCache.BindStore(cacheStore)
	if err := eng.PopulateSignerCache([]signerapi.KeyInfo{
		{Address: staleAddr, KeyType: "ed25519"},
	}); err != nil {
		t.Fatalf("PopulateSignerCache(stale) error = %v", err)
	}
	if err := eng.SaveSignerCache(); err != nil {
		t.Fatalf("SaveSignerCache(stale) error = %v", err)
	}

	persistedBefore := cache.LoadSignerCacheFromStore(cacheStore)
	if got := persistedBefore.Keys[staleAddr]; got != "ed25519" {
		t.Fatalf("persisted stale signer key = %q, want ed25519", got)
	}

	eng.handleConnectionClosed(nil)()
	if got := eng.SignerCache.Count(); got != 0 {
		t.Fatalf("SignerCache.Count() after disconnect = %d, want 0", got)
	}

	if err := eng.PopulateSignerCache([]signerapi.KeyInfo{
		{Address: freshAddr, KeyType: "aplane.falcon1024.v1"},
	}); err != nil {
		t.Fatalf("PopulateSignerCache(fresh) error = %v", err)
	}
	if err := eng.SaveSignerCache(); err != nil {
		t.Fatalf("SaveSignerCache(fresh) error = %v", err)
	}

	if eng.SignerCache.HasAddress(staleAddr) {
		t.Fatalf("stale signer address %q remained in in-memory cache after reconnect", staleAddr)
	}
	if got := eng.SignerCache.GetKeyType(freshAddr); got != "aplane.falcon1024.v1" {
		t.Fatalf("fresh signer key type = %q, want aplane.falcon1024.v1", got)
	}

	reloaded := newEngine()
	if reloaded.SignerCache.HasAddress(staleAddr) {
		t.Fatalf("stale signer address %q remained in persisted cache after reconnect", staleAddr)
	}
	if got := reloaded.SignerCache.GetKeyType(freshAddr); got != "aplane.falcon1024.v1" {
		t.Fatalf("reloaded fresh signer key type = %q, want aplane.falcon1024.v1", got)
	}
	if got := reloaded.SignerCache.Count(); got != 1 {
		t.Fatalf("reloaded SignerCache.Count() = %d, want 1", got)
	}
}

func TestCanSignForAddressRejectsUnknownCachedKeyType(t *testing.T) {
	eng, err := NewEngine("testnet")
	if err != nil {
		t.Fatal(err)
	}
	address := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	if err := eng.PopulateSignerCache([]signerapi.KeyInfo{{Address: address, KeyType: ""}}); err != nil {
		t.Fatal(err)
	}
	canSign, kind := eng.CanSignForAddressWithKind(address)
	if canSign || kind != "" {
		t.Fatalf("CanSignForAddressWithKind() = %t/%q, want false/empty", canSign, kind)
	}
}

func TestRefreshAuthAddressWithContextUpdatesSingleEntry(t *testing.T) {
	address := testAddr(20)
	authAddress := testAddr(21)
	otherAddress := testAddr(22)
	otherAuth := testAddr(23)

	transport := newAccountMockTransport(t)
	transport.addAccountFull(models.Account{
		Address:                     address,
		AuthAddr:                    authAddress,
		Amount:                      1_000_000,
		AmountWithoutPendingRewards: 1_000_000,
		MinBalance:                  100_000,
		Status:                      "Offline",
	})
	eng := setupEngineWithMockAlgod(t, transport)
	eng.AuthCache.AuthAddresses = map[string]string{
		otherAddress: otherAuth,
	}

	got, err := eng.RefreshAuthAddressWithContext(context.Background(), address)
	if err != nil {
		t.Fatalf("RefreshAuthAddressWithContext() error = %v", err)
	}
	if got != authAddress {
		t.Fatalf("RefreshAuthAddressWithContext() auth = %q, want %q", got, authAddress)
	}
	if cached, ok := eng.AuthCache.GetAuthAddress(address); !ok || cached != authAddress {
		t.Fatalf("auth cache entry = %q, %v; want %q, true", cached, ok, authAddress)
	}
	if cached, ok := eng.AuthCache.GetAuthAddress(otherAddress); !ok || cached != otherAuth {
		t.Fatalf("unrelated auth cache entry = %q, %v; want %q, true", cached, ok, otherAuth)
	}
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	counts := make(map[string]int, len(got))
	for _, s := range got {
		counts[s]++
	}
	for _, s := range want {
		if counts[s] == 0 {
			return false
		}
		counts[s]--
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}
